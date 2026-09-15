import httpx
import pytest

from noctis.agents.base_agent import AgentContext
from noctis.agents.sqli import SQLiAgent
from noctis.config.settings import Settings
from noctis.core.model_router import ModelRouter
from noctis.core.scope import ScopeEngine
from noctis.core.workspace import WorkspaceManager


def _context(tmp_path, node_data) -> AgentContext:
    settings = Settings(workspace_dir=tmp_path / "workspaces", requests_per_second=0, _env_file=None)
    manager = WorkspaceManager(settings)
    ws = manager.create(target="https://example.com")
    scope = ScopeEngine(target="https://example.com")
    return AgentContext(
        node_id="endpoint::GET::https://example.com/search?q=test",
        node_data=node_data,
        scope=scope,
        model_router=ModelRouter(settings),
        settings=settings,
        workspace_id=ws.id,
        workspace_manager=manager,
    )


@pytest.mark.asyncio
async def test_error_based_sqli_confirmed(tmp_path, httpx_mock):
    node_data = {"type": "endpoint", "method": "GET", "url": "https://example.com/search?q=test"}

    def responder(request: httpx.Request) -> httpx.Response:
        if "%27" in str(request.url) or "'" in str(request.url):
            return httpx.Response(200, text="You have an error in your SQL syntax near '''")
        return httpx.Response(200, text="normal results page")

    httpx_mock.add_callback(responder, is_reusable=True)
    agent = SQLiAgent(_context(tmp_path, node_data))
    result = await agent.execute()

    assert result.found is True
    assert "sql syntax" in result.evidence.lower()


@pytest.mark.asyncio
async def test_no_sqli_when_nothing_differs(tmp_path, httpx_mock):
    node_data = {"type": "endpoint", "method": "GET", "url": "https://example.com/search?q=test"}
    httpx_mock.add_response(text="always the same boring page", is_reusable=True)

    agent = SQLiAgent(_context(tmp_path, node_data))
    result = await agent.execute()

    assert result.found is False


@pytest.mark.asyncio
async def test_no_target_when_no_params(tmp_path):
    node_data = {"type": "endpoint", "method": "GET", "url": "https://example.com/"}
    agent = SQLiAgent(_context(tmp_path, node_data))
    result = await agent.execute()
    assert result.found is False
    assert "no injectable parameters" in result.notes
