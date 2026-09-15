"""Validator: independently re-confirms every EXPLOIT-stage finding before it's
kept. Each finding's agent is re-instantiated fresh and run again from
scratch (not just re-checking the same cached request) -- if it doesn't
reproduce, it's discarded rather than silently dropped, so the tester can see
what got filtered and why (matches the "no exploit, no report" principle
without hiding the filtering itself, in keeping with this being a tool a
tester works closely with, not a black box).

Also assigns CVSS v3.1 scoring + severity, OWASP/MITRE ATT&CK classification,
and organizes evidence (request/response, PoC script, and any screenshot the
agent already captured) per finding.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from noctis.config.settings import Settings
from noctis.core.model_router import ModelRouter
from noctis.core.scope import ScopeEngine
from noctis.core.workspace import WorkspaceManager
from noctis.evidence.store import EvidenceStore, compute_finding_id
from noctis.validator.classification import classify
from noctis.validator.cvss import base_score, severity_for, vector_for
from noctis.validator.poc_generator import generate_poc_script

logger = logging.getLogger("noctis.validator")


@dataclass
class ValidatedFinding:
    finding_id: str
    agent_type: str
    node_id: str
    reproduced: bool
    rationale: str
    payload: str = ""
    request: str = ""
    response: str = ""
    evidence: str = ""
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: str | None = None
    owasp_category: str | None = None
    attack_tactic: str | None = None
    attack_technique: str | None = None
    cve_refs: list[str] = field(default_factory=list)
    evidence_dir: str | None = None
    screenshot_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "agent_type": self.agent_type,
            "node_id": self.node_id,
            "reproduced": self.reproduced,
            "rationale": self.rationale,
            "payload": self.payload,
            "request": self.request,
            "response": self.response,
            "evidence": self.evidence,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "severity": self.severity,
            "owasp_category": self.owasp_category,
            "attack_tactic": self.attack_tactic,
            "attack_technique": self.attack_technique,
            "cve_refs": self.cve_refs,
            "evidence_dir": self.evidence_dir,
            "screenshot_path": self.screenshot_path,
        }


class Validator:
    def __init__(
        self,
        workspace_manager: WorkspaceManager,
        workspace_id: str,
        scope: ScopeEngine,
        settings: Settings,
        model_router: ModelRouter,
    ):
        self.workspace_manager = workspace_manager
        self.workspace_id = workspace_id
        self.scope = scope
        self.settings = settings
        self.model_router = model_router
        self.evidence = EvidenceStore(workspace_manager, workspace_id)

    async def validate_findings(
        self, exploit_result: dict[str, Any], graph_result: dict[str, Any], *, repo_path: str | None
    ) -> dict[str, Any]:
        findings = exploit_result.get("findings", [])
        nodes_by_id = {n["id"]: n for n in graph_result.get("graph", {}).get("nodes", [])}

        validated: list[ValidatedFinding] = []
        for task in findings:
            agent_type = task["agent_type"]
            node_id = task["node_id"]
            finding_id = compute_finding_id(agent_type, node_id)
            node_data = nodes_by_id.get(node_id, {})

            replay_result = await self._replay(agent_type, node_id, node_data, task, repo_path=repo_path)

            if replay_result is None or not replay_result.get("found"):
                reason = "did not reproduce on independent replay"
                if replay_result is None:
                    reason = "agent unavailable or errored during replay"
                self.workspace_manager.log(self.workspace_id, f"[validator] discarded {finding_id}: {reason}")
                validated.append(
                    ValidatedFinding(
                        finding_id=finding_id,
                        agent_type=agent_type,
                        node_id=node_id,
                        reproduced=False,
                        rationale=reason,
                        payload=task.get("result", {}).get("payload", "") if task.get("result") else "",
                    )
                )
                continue

            finding = self._score_and_store(finding_id, agent_type, node_id, node_data, replay_result)
            self.workspace_manager.log(
                self.workspace_id, f"[validator] confirmed {finding_id}: severity={finding.severity} cvss={finding.cvss_score}"
            )
            validated.append(finding)

        return {
            "findings": [f.to_dict() for f in validated],
            "confirmed": sum(1 for f in validated if f.reproduced),
            "discarded": sum(1 for f in validated if not f.reproduced),
        }

    async def _replay(
        self,
        agent_type: str,
        node_id: str,
        node_data: dict[str, Any],
        task: dict[str, Any],
        *,
        repo_path: str | None,
    ) -> dict[str, Any] | None:
        from noctis.agents.base_agent import AgentContext
        from noctis.agents.registry import AGENT_REGISTRY

        agent_cls = AGENT_REGISTRY.get(agent_type)
        if agent_cls is None:
            return None

        context = AgentContext(
            node_id=node_id,
            node_data=node_data,
            scope=self.scope,
            model_router=self.model_router,
            settings=self.settings,
            workspace_id=self.workspace_id,
            workspace_manager=self.workspace_manager,
            rationale=task.get("rationale", ""),
            repo_path=repo_path,
        )
        agent = agent_cls(context)
        try:
            result = await agent.execute()
        except Exception as exc:
            logger.exception("Replay failed for %s on %s", agent_type, node_id)
            return {"found": False, "notes": f"replay raised: {exc}"}
        return result.to_dict()

    def _score_and_store(
        self, finding_id: str, agent_type: str, node_id: str, node_data: dict[str, Any], result: dict[str, Any]
    ) -> ValidatedFinding:
        vector = vector_for(agent_type, node_data)
        score = base_score(vector)
        severity = severity_for(score)
        classification = classify(agent_type, result.get("evidence", ""))

        self.evidence.save_request_response(finding_id, result.get("request", ""), result.get("response", ""))
        poc_script = generate_poc_script(agent_type, finding_id, result)
        self.evidence.save_poc_script(finding_id, poc_script)

        return ValidatedFinding(
            finding_id=finding_id,
            agent_type=agent_type,
            node_id=node_id,
            reproduced=True,
            rationale="reproduced on independent replay",
            payload=result.get("payload", ""),
            request=result.get("request", ""),
            response=result.get("response", ""),
            evidence=result.get("evidence", ""),
            cvss_score=score,
            cvss_vector=vector.to_vector_string(),
            severity=severity,
            owasp_category=classification.owasp_category,
            attack_tactic=classification.attack_tactic,
            attack_technique=classification.attack_technique,
            cve_refs=[],
            evidence_dir=str(self.evidence.finding_dir(finding_id)),
            screenshot_path=result.get("screenshot_path"),
        )
