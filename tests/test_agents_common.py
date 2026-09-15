"""Shared context builder for agent tests."""
from __future__ import annotations

from noctis.agents.base_agent import AgentContext
from noctis.config.settings import Settings
from noctis.core.model_router import ModelRouter
from noctis.core.scope import ScopeEngine
from noctis.core.workspace import WorkspaceManager


def build_context(tmp_path, node_data: dict, *, target: str = "https://example.com", **settings_kwargs) -> AgentContext:
    settings = Settings(workspace_dir=tmp_path / "workspaces", requests_per_second=0, _env_file=None, **settings_kwargs)
    manager = WorkspaceManager(settings)
    ws = manager.create(target=target)
    scope = ScopeEngine(target=target)
    return AgentContext(
        node_id="test::node",
        node_data=node_data,
        scope=scope,
        model_router=ModelRouter(settings),
        settings=settings,
        workspace_id=ws.id,
        workspace_manager=manager,
    )
