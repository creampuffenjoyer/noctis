"""Shared base for every HTTP-driven exploitation agent: owns a ScopedHttpClient,
extracts an injection target from the graph node, and provides a generic
"re-check before reporting" validate() so a flaky single request can't turn
into a false finding.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable

import httpx

from noctis.agents.base_agent import AgentContext, AgentResult, BaseAgent
from noctis.agents.http_client import ScopedHttpClient
from noctis.agents.targeting import InjectionTarget, build_target


class HttpAgent(BaseAgent):
    def __init__(self, context: AgentContext):
        super().__init__(context)
        self.client = ScopedHttpClient(context.scope, context.settings)
        self.target: InjectionTarget | None = None
        # set by run() when it finds something, so validate() can re-check it
        self._recheck: Callable[[], Awaitable[bool]] | None = None

    async def setup(self) -> None:
        self.target = build_target(self.context.node_data)

    async def cleanup(self) -> None:
        await self.client.aclose()

    def no_target_result(self, reason: str = "node has no injectable parameters") -> AgentResult:
        return AgentResult(found=False, notes=reason)

    async def validate(self, result: AgentResult) -> AgentResult:
        if not result.found or self._recheck is None:
            return result
        try:
            reproduced = await self._recheck()
        except httpx.HTTPError as exc:
            result.found = False
            result.notes = f"{result.notes} | re-check failed: {exc}".strip(" |")
            return result
        if not reproduced:
            result.found = False
            result.notes = f"{result.notes} | did not reproduce on re-check, discarded".strip(" |")
        else:
            result.notes = f"{result.notes} | reproduced on re-check".strip(" |")
        return result

    async def report(self, result: AgentResult) -> AgentResult:
        return result

    @staticmethod
    def _format_request(method: str, url: str, body: dict[str, str] | None = None) -> str:
        if body:
            return f"{method} {url}\nbody: {body}"
        return f"{method} {url}"

    @staticmethod
    def _format_response(response: httpx.Response, limit: int = 500) -> str:
        text = response.text[:limit]
        return f"HTTP {response.status_code} ({len(response.text)} bytes)\n{text}"

    @staticmethod
    def _poc_request(
        method: str, url: str, data: dict[str, str] | None = None, content: str | None = None
    ) -> dict:
        return {"method": method, "url": url, "data": data, "content": content}
