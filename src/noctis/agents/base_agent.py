"""Base class all exploitation agents (Phase 4: SQLi, XSS, SSRF, Auth, IDOR,
RCE, LFI, XXE) will inherit. Defines the standard setup -> run -> validate ->
report lifecycle and the result shape every agent must return.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from noctis.config.settings import Settings
from noctis.core.model_router import ModelRouter
from noctis.core.scope import ScopeEngine
from noctis.core.workspace import WorkspaceManager


@dataclass
class AgentResult:
    found: bool
    payload: str = ""
    request: str = ""
    response: str = ""
    evidence: str = ""
    notes: str = ""
    # structured replay recipe for the Validator/PoC generator (Phase 5), when
    # the finding is a plain HTTP request the Validator can resend directly.
    # None for agents where that doesn't make sense (XSS needs a browser, JWT
    # forgery needs custom headers) -- left for a documentation-style PoC instead.
    poc_request: dict[str, Any] | None = None
    # path to a saved screenshot on disk, if the confirming agent captured one
    screenshot_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "found": self.found,
            "payload": self.payload,
            "request": self.request,
            "response": self.response,
            "evidence": self.evidence,
            "notes": self.notes,
            "poc_request": self.poc_request,
            "screenshot_path": self.screenshot_path,
        }


@dataclass
class AgentContext:
    """Everything an agent needs to attack one node, without ever touching a
    model SDK or the network directly -- it goes through these.
    """

    node_id: str
    node_data: dict[str, Any]
    scope: ScopeEngine
    model_router: ModelRouter
    settings: Settings
    workspace_id: str
    workspace_manager: WorkspaceManager
    rationale: str = ""
    repo_path: str | None = None


class BaseAgent(ABC):
    agent_type: str = "base"

    def __init__(self, context: AgentContext):
        self.context = context

    @abstractmethod
    async def setup(self) -> None:
        """Prepare payloads, sessions, or tooling before the attack runs."""

    @abstractmethod
    async def run(self) -> AgentResult:
        """Execute the attack attempt(s) and return a candidate result."""

    @abstractmethod
    async def validate(self, result: AgentResult) -> AgentResult:
        """Confirm the candidate result actually reproduces before it's kept."""

    @abstractmethod
    async def report(self, result: AgentResult) -> AgentResult:
        """Finalize evidence formatting; return the result as-is if nothing to add."""

    async def execute(self) -> AgentResult:
        await self.setup()
        try:
            result = await self.run()
            result = await self.validate(result)
            result = await self.report(result)
            return result
        finally:
            await self.cleanup()

    async def cleanup(self) -> None:
        """Optional teardown (close HTTP clients, browsers, etc). No-op by default."""
        return None
