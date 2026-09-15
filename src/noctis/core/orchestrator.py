"""Orchestrator: drives the scan pipeline stage by stage, with resume + error recovery.

Each stage's output is snapshotted to the workspace after it completes, so a
crash or Ctrl-C can be resumed with `noctis resume --workspace <id>` without
re-running finished stages.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from enum import StrEnum
from typing import Any

from noctis.config.settings import Settings, get_settings
from noctis.core.model_router import ModelRouter
from noctis.core.scope import ScopeEngine
from noctis.core.workspace import Workspace, WorkspaceManager

logger = logging.getLogger("noctis.orchestrator")

StageCallback = Callable[["PipelineStage", str], None]


class PipelineStage(StrEnum):
    RECON = "recon"
    GRAPH = "graph"
    RISK = "risk"
    PLANNER = "planner"
    EXPLOIT = "exploit"
    VALIDATE = "validate"
    REPORT = "report"


class RunMode(StrEnum):
    """CONTINUOUS runs every implemented stage back to back (still respecting
    the EXPLOIT --exploit gate). GUIDED pauses after every single stage so the
    tester reviews and explicitly `resume`s before the next one runs -- the
    same mechanism the EXPLOIT gate already uses, generalized to every stage.
    """

    CONTINUOUS = "continuous"
    GUIDED = "guided"


# Stages implemented so far. Anything past this point is logged and skipped
# gracefully rather than crashing the pipeline, since later phases (risk
# scoring, exploitation agents, validation, reporting) aren't built yet.
IMPLEMENTED_STAGES = {
    PipelineStage.RECON,
    PipelineStage.GRAPH,
    PipelineStage.RISK,
    PipelineStage.PLANNER,
    PipelineStage.EXPLOIT,
    PipelineStage.VALIDATE,
}

ALL_STAGES = list(PipelineStage)


class Orchestrator:
    def __init__(
        self,
        workspace: Workspace,
        workspace_manager: WorkspaceManager,
        scope: ScopeEngine,
        settings: Settings | None = None,
        model_router: ModelRouter | None = None,
        on_stage: StageCallback | None = None,
    ):
        self.workspace = workspace
        self.workspace_manager = workspace_manager
        self.scope = scope
        self.settings = settings or get_settings()
        self.model_router = model_router or ModelRouter(self.settings)
        self.on_stage = on_stage or (lambda stage, status: None)

    def _notify(self, stage: PipelineStage, status: str) -> None:
        self.workspace_manager.log(self.workspace.id, f"[{stage.value}] {status}")
        self.on_stage(stage, status)

    @staticmethod
    def _would_continue_automatically(completed_stage: PipelineStage, run_exploit: bool) -> bool:
        """Whether the stage after `completed_stage` would run on its own
        without guided mode's extra pause -- i.e. it's implemented and isn't
        itself gated behind an unmet --exploit flag. Used so guided mode
        doesn't insert a redundant pause right before a gate that would have
        stopped the pipeline anyway (the EXPLOIT gate, or the not-yet-
        implemented boundary), which would otherwise print two pause
        messages back to back for the same stopping point.
        """
        next_index = ALL_STAGES.index(completed_stage) + 1
        if next_index >= len(ALL_STAGES):
            return False
        next_stage = ALL_STAGES[next_index]
        if next_stage not in IMPLEMENTED_STAGES:
            return False
        if next_stage is PipelineStage.EXPLOIT and not run_exploit:
            return False
        return True

    async def run(
        self,
        repo_path: str | None = None,
        resume: bool = False,
        run_exploit: bool = False,
        mode: RunMode = RunMode.CONTINUOUS,
        stop_check: Callable[[], bool] | None = None,
    ) -> dict[str, Any]:
        results: dict[str, Any] = {}
        self.workspace_manager.update_status(self.workspace.id, "running")
        stop_check = stop_check or (lambda: False)

        for stage in ALL_STAGES:
            if resume:
                cached = self.workspace_manager.load_stage_data(self.workspace.id, stage.value)
                if cached is not None:
                    self._notify(stage, "skipped (already completed, resumed from cache)")
                    results[stage.value] = cached
                    continue

            # checked at a stage boundary only, never mid-stage: a graceful
            # stop lets whatever's currently running finish first
            if stop_check():
                self._notify(stage, "stop requested - pausing here, rerun with resume to continue")
                self.workspace_manager.update_status(self.workspace.id, "paused", stage=stage.value)
                break

            if stage is PipelineStage.EXPLOIT and not run_exploit:
                self._notify(stage, "queue ready for review - rerun with --exploit to launch agents")
                self.workspace_manager.update_status(self.workspace.id, "paused", stage=stage.value)
                break

            if stage not in IMPLEMENTED_STAGES:
                self._notify(stage, "not yet implemented - stopping pipeline here")
                self.workspace_manager.update_status(self.workspace.id, "paused", stage=stage.value)
                break

            self._notify(stage, "started")
            try:
                stage_result = await self._run_stage(stage, results, repo_path=repo_path)
            except Exception as exc:
                logger.exception("Stage %s failed", stage.value)
                self._notify(stage, f"failed: {exc}")
                self.workspace_manager.update_status(self.workspace.id, "failed", stage=stage.value)
                raise

            results[stage.value] = stage_result
            self.workspace_manager.save_stage_data(self.workspace.id, stage.value, stage_result)
            self._notify(stage, "completed")

            if mode is RunMode.GUIDED and self._would_continue_automatically(stage, run_exploit):
                self._notify(stage, "guided mode - phase complete, rerun with resume to continue")
                self.workspace_manager.update_status(self.workspace.id, "paused", stage=stage.value)
                break

        else:
            self.workspace_manager.update_status(self.workspace.id, "completed")

        return results

    async def _run_stage(
        self, stage: PipelineStage, prior_results: dict[str, Any], *, repo_path: str | None
    ) -> dict[str, Any]:
        if stage is PipelineStage.RECON:
            return await self._run_recon(repo_path=repo_path)
        if stage is PipelineStage.GRAPH:
            return await self._run_graph(prior_results.get("recon", {}))
        if stage is PipelineStage.RISK:
            return await self._run_risk(prior_results.get("graph", {}))
        if stage is PipelineStage.PLANNER:
            return await self._run_planner(prior_results.get("graph", {}), prior_results.get("risk", {}))
        if stage is PipelineStage.EXPLOIT:
            return await self._run_exploit(
                prior_results.get("planner", {}), prior_results.get("graph", {}), repo_path=repo_path
            )
        if stage is PipelineStage.VALIDATE:
            return await self._run_validate(
                prior_results.get("exploit", {}), prior_results.get("graph", {}), repo_path=repo_path
            )
        raise NotImplementedError(f"Stage '{stage.value}' has no handler yet")

    async def _run_recon(self, *, repo_path: str | None) -> dict[str, Any]:
        from noctis.engines.recon.code_analysis import analyze_repo
        from noctis.engines.recon.web_discovery import discover

        web_result = await discover(self.workspace.target, self.scope, self.settings)
        code_result = analyze_repo(repo_path) if repo_path else None

        return {
            "web": web_result.to_dict(),
            "code": code_result.to_dict() if code_result else None,
        }

    async def _run_graph(self, recon_result: dict[str, Any]) -> dict[str, Any]:
        from noctis.engines.graph.attack_surface import build_attack_surface_graph

        graph = build_attack_surface_graph(recon_result)
        return graph.to_dict()

    async def _run_risk(self, graph_result: dict[str, Any]) -> dict[str, Any]:
        from noctis.engines.graph.attack_surface import AttackSurfaceGraph
        from noctis.engines.risk.risk_engine import RiskEngine

        asg = AttackSurfaceGraph.from_dict(graph_result)
        engine = RiskEngine()
        scores = engine.score_graph(asg)
        chains = engine.detect_chains(asg, scores)

        return {
            "scores": [s.to_dict() for s in scores],
            "chains": [c.to_dict() for c in chains],
        }

    async def _run_planner(self, graph_result: dict[str, Any], risk_result: dict[str, Any]) -> dict[str, Any]:
        from noctis.engines.graph.attack_surface import AttackSurfaceGraph
        from noctis.engines.planner.test_planner import TestPlanner
        from noctis.engines.risk.risk_engine import NodeRiskScore

        asg = AttackSurfaceGraph.from_dict(graph_result)
        scores = [
            NodeRiskScore(
                node_id=s["node_id"],
                node_type=s["node_type"],
                exploitability=s["exploitability"],
                impact=s["impact"],
                score=s["score"],
                factors=s["factors"],
            )
            for s in risk_result.get("scores", [])
        ]

        planner = TestPlanner()
        queue = planner.build_queue(asg, scores)
        return {"queue": [t.to_dict() for t in queue]}

    async def _run_exploit(
        self, planner_result: dict[str, Any], graph_result: dict[str, Any], *, repo_path: str | None
    ) -> dict[str, Any]:
        from noctis.agents.base_agent import AgentContext
        from noctis.agents.registry import AGENT_REGISTRY
        from noctis.engines.planner.test_planner import ConcurrencyManager

        queue = planner_result.get("queue", [])
        nodes_by_id = {n["id"]: n for n in graph_result.get("graph", {}).get("nodes", [])}
        concurrency = ConcurrencyManager(self.settings.max_workers)

        async def run_task(task: dict[str, Any]) -> dict[str, Any]:
            agent_cls = AGENT_REGISTRY.get(task["agent_type"])
            if agent_cls is None:
                return {**task, "result": None, "error": f"no agent registered for '{task['agent_type']}'"}

            context = AgentContext(
                node_id=task["node_id"],
                node_data=nodes_by_id.get(task["node_id"], {}),
                scope=self.scope,
                model_router=self.model_router,
                settings=self.settings,
                workspace_id=self.workspace.id,
                workspace_manager=self.workspace_manager,
                rationale=task["rationale"],
                repo_path=repo_path,
            )
            agent = agent_cls(context)
            try:
                result = await agent.execute()
            except Exception as exc:
                logger.exception("agent %s failed on node %s", task["agent_type"], task["node_id"])
                return {**task, "result": None, "error": str(exc)}
            return {**task, "result": result.to_dict(), "error": None}

        task_results = await concurrency.run_tasks(queue, run_task)
        findings = [t for t in task_results if t.get("result") and t["result"].get("found")]

        return {"tasks": task_results, "findings": findings, "total": len(queue), "found": len(findings)}

    async def _run_validate(
        self, exploit_result: dict[str, Any], graph_result: dict[str, Any], *, repo_path: str | None
    ) -> dict[str, Any]:
        from noctis.validator.validator import Validator

        validator = Validator(
            workspace_manager=self.workspace_manager,
            workspace_id=self.workspace.id,
            scope=self.scope,
            settings=self.settings,
            model_router=self.model_router,
        )
        return await validator.validate_findings(exploit_result, graph_result, repo_path=repo_path)
