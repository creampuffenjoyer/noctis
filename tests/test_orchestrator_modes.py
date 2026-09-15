import httpx
import pytest

from noctis.config.settings import Settings
from noctis.core.orchestrator import Orchestrator, PipelineStage, RunMode
from noctis.core.scope import ScopeEngine
from noctis.core.workspace import WorkspaceManager


def _orchestrator(tmp_path, httpx_mock):
    httpx_mock.add_response(text="<html><body>hi</body></html>", is_reusable=True)
    settings = Settings(workspace_dir=tmp_path / "workspaces", requests_per_second=0, _env_file=None)
    manager = WorkspaceManager(settings)
    ws = manager.create(target="https://example.com")
    scope = ScopeEngine(target="https://example.com")
    return Orchestrator(workspace=ws, workspace_manager=manager, scope=scope, settings=settings), manager, ws


@pytest.mark.asyncio
async def test_guided_mode_pauses_after_first_stage(tmp_path, httpx_mock):
    orchestrator, manager, ws = _orchestrator(tmp_path, httpx_mock)

    results = await orchestrator.run(mode=RunMode.GUIDED)

    assert set(results.keys()) == {"recon"}
    reloaded = manager.get(ws.id)
    assert reloaded.status == "paused"
    assert reloaded.stage == "recon"


@pytest.mark.asyncio
async def test_guided_mode_resume_advances_one_stage_at_a_time(tmp_path, httpx_mock):
    orchestrator, manager, ws = _orchestrator(tmp_path, httpx_mock)

    await orchestrator.run(mode=RunMode.GUIDED)
    results = await orchestrator.run(resume=True, mode=RunMode.GUIDED)

    assert set(results.keys()) == {"recon", "graph"}
    reloaded = manager.get(ws.id)
    assert reloaded.stage == "graph"


@pytest.mark.asyncio
async def test_continuous_mode_runs_through_planner_without_pausing(tmp_path, httpx_mock):
    orchestrator, manager, ws = _orchestrator(tmp_path, httpx_mock)

    results = await orchestrator.run(mode=RunMode.CONTINUOUS)

    assert set(results.keys()) == {"recon", "graph", "risk", "planner"}
    reloaded = manager.get(ws.id)
    assert reloaded.status == "paused"
    assert reloaded.stage == "exploit"  # gated behind --exploit regardless of mode


@pytest.mark.asyncio
async def test_stop_check_pauses_at_next_boundary_not_mid_run(tmp_path, httpx_mock):
    orchestrator, manager, ws = _orchestrator(tmp_path, httpx_mock)

    calls = {"n": 0}

    def stop_after_first_check() -> bool:
        calls["n"] += 1
        return calls["n"] > 1  # let the first boundary check pass, stop before the second stage

    results = await orchestrator.run(mode=RunMode.CONTINUOUS, stop_check=stop_after_first_check)

    assert set(results.keys()) == {"recon"}
    reloaded = manager.get(ws.id)
    assert reloaded.status == "paused"
    assert reloaded.stage == "graph"


@pytest.mark.asyncio
async def test_guided_mode_does_not_double_pause_before_exploit_gate(tmp_path, httpx_mock):
    orchestrator, manager, ws = _orchestrator(tmp_path, httpx_mock)
    statuses = []
    orchestrator.on_stage = lambda stage, status: statuses.append((stage, status))

    for _ in range(4):  # recon, graph, risk, planner
        await orchestrator.run(resume=(len(statuses) > 0), mode=RunMode.GUIDED)

    # planner's completion should be followed directly by the exploit-gate message,
    # not an extra redundant "guided mode" pause message for the same stopping point
    planner_related = [s for s in statuses if s[0] is PipelineStage.PLANNER or s[0] is PipelineStage.EXPLOIT]
    assert planner_related[-1] == (PipelineStage.EXPLOIT, "queue ready for review - rerun with --exploit to launch agents")
    assert (PipelineStage.PLANNER, "guided mode - phase complete, rerun with resume to continue") not in statuses
