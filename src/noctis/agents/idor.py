"""IDOR agent: mutates numeric IDs and UUIDs in the URL path and query string
and checks whether an adjacent object is returned without an authorization
error. This is a single-session heuristic -- without a second authenticated
identity we can't prove it's *another user's* data, only that the object
reference isn't gated by an ownership check. That caveat is spelled out in
every finding's evidence so it doesn't get mistaken for a stronger claim.
"""
from __future__ import annotations

import re
import uuid
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from noctis.agents.base_agent import AgentResult
from noctis.agents.http_agent import HttpAgent

NOT_FOUND_SIGNATURES = ["not found", "does not exist", "no such", "forbidden", "unauthorized", "access denied", "404"]
UUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
NUMERIC_PATTERN = re.compile(r"^\d+$")


class IDORAgent(HttpAgent):
    agent_type = "idor"

    async def run(self) -> AgentResult:
        if self.target is None or self.target.is_form:
            return self.no_target_result("IDOR probing needs a URL-addressable object reference, not a form submission")

        baseline_url = self.target.url
        try:
            baseline = await self.client.get(baseline_url)
        except Exception as exc:
            return AgentResult(found=False, notes=f"baseline request failed: {exc}")

        if baseline.status_code >= 400:
            return AgentResult(found=False, notes="baseline itself errors, nothing to compare against")

        for param, mutated_url, mutated_value in self._path_candidates(baseline_url):
            result = await self._probe(param, mutated_url, mutated_value, baseline)
            if result:
                return result

        for param, mutated_url, mutated_value in self._query_candidates(baseline_url):
            result = await self._probe(param, mutated_url, mutated_value, baseline)
            if result:
                return result

        return AgentResult(found=False, notes="no adjacent object reference returned distinct data without an authorization check")

    async def _probe(self, param: str, mutated_url: str, mutated_value: str, baseline) -> AgentResult | None:
        try:
            self.context.scope.assert_in_scope(mutated_url)
            mutated = await self.client.get(mutated_url)
        except Exception:
            return None

        if mutated.status_code >= 400 or self._looks_like_denial(mutated.text):
            return None
        if mutated.text.strip() == baseline.text.strip():
            return None  # identical content, not a distinguishable object

        async def recheck(u=mutated_url) -> bool:
            r = await self.client.get(u)
            return r.status_code < 400 and not self._looks_like_denial(r.text)

        self._recheck = recheck
        return AgentResult(
            found=True,
            payload=mutated_value,
            request=self._format_request("GET", mutated_url),
            response=self._format_response(mutated),
            evidence=(
                f"changing '{param}' to '{mutated_value}' returned distinct, non-error content "
                f"({mutated.status_code}) with the same session -- object reference is not "
                f"gated by an ownership check (single-session heuristic, not confirmed against a "
                f"second identity)"
            ),
        )

    def _path_candidates(self, url: str) -> list[tuple[str, str, str]]:
        parsed = urlparse(url)
        segments = parsed.path.split("/")
        candidates = []
        for i, segment in enumerate(segments):
            mutated_segment = self._mutate(segment)
            if mutated_segment is None:
                continue
            new_segments = list(segments)
            new_segments[i] = mutated_segment
            new_path = "/".join(new_segments)
            mutated_url = urlunparse(parsed._replace(path=new_path))
            candidates.append((f"path segment {i}", mutated_url, mutated_segment))
        return candidates

    def _query_candidates(self, url: str) -> list[tuple[str, str, str]]:
        parsed = urlparse(url)
        query = {k: v[0] if v else "" for k, v in parse_qs(parsed.query).items()}
        candidates = []
        for key, value in query.items():
            mutated_value = self._mutate(value)
            if mutated_value is None:
                continue
            new_query = {**query, key: mutated_value}
            mutated_url = urlunparse(parsed._replace(query=urlencode(new_query)))
            candidates.append((key, mutated_url, mutated_value))
        return candidates

    @staticmethod
    def _mutate(value: str) -> str | None:
        if NUMERIC_PATTERN.match(value):
            n = int(value)
            return str(n + 1) if n >= 0 else str(n - 1)
        if UUID_PATTERN.match(value):
            return str(uuid.uuid4())
        return None

    @staticmethod
    def _looks_like_denial(text: str) -> bool:
        lowered = text.lower()
        return any(sig in lowered for sig in NOT_FOUND_SIGNATURES)
