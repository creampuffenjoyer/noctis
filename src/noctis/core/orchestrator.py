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


# Stages implemented so far. Anything past this point is logged and skipped
# gracefully rather than crashing the pipeline, since later phases (risk
# scoring, exploitation agents, validation, reporting) aren't built yet.
IMPLEMENTED_STAGES = {PipelineStage.RECON, PipelineStage.GRAPH}

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

    async def run(self, repo_path: str | None = None, resume: bool = False) -> dict[str, Any]:
        results: dict[str, Any] = {}
        self.workspace_manager.update_status(self.workspace.id, "running")

        for stage in ALL_STAGES:
            if resume:
                cached = self.workspace_manager.load_stage_data(self.workspace.id, stage.value)
                if cached is not None:
                    self._notify(stage, "skipped (already completed, resumed from cache)")
                    results[stage.value] = cached
                    continue

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
