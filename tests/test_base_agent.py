import asyncio

from noctis.agents.base_agent import AgentContext, AgentResult, BaseAgent
from noctis.config.settings import Settings
from noctis.core.model_router import ModelRouter
from noctis.core.scope import ScopeEngine
from noctis.core.workspace import WorkspaceManager


class RecordingAgent(BaseAgent):
    agent_type = "dummy"

    def __init__(self, context: AgentContext):
        super().__init__(context)
        self.calls: list[str] = []

    async def setup(self) -> None:
        self.calls.append("setup")

    async def run(self) -> AgentResult:
        self.calls.append("run")
        return AgentResult(found=True, payload="' OR 1=1--")

    async def validate(self, result: AgentResult) -> AgentResult:
        self.calls.append("validate")
        result.notes = "reproduced on replay"
        return result

    async def report(self, result: AgentResult) -> AgentResult:
        self.calls.append("report")
        result.evidence = "screenshot.png"
        return result


def _context(tmp_path) -> AgentContext:
    settings = Settings(workspace_dir=tmp_path / "workspaces", _env_file=None)
    manager = WorkspaceManager(settings)
    ws = manager.create(target="https://example.com")
    scope = ScopeEngine(target="https://example.com")
    return AgentContext(
        node_id="endpoint::GET::https://example.com/",
        node_data={},
        scope=scope,
        model_router=ModelRouter(settings),
        settings=settings,
        workspace_id=ws.id,
        workspace_manager=manager,
    )


def test_execute_runs_lifecycle_in_order(tmp_path):
    agent = RecordingAgent(_context(tmp_path))
    result = asyncio.run(agent.execute())

    assert agent.calls == ["setup", "run", "validate", "report"]
    assert result.found is True
    assert result.notes == "reproduced on replay"
    assert result.evidence == "screenshot.png"
