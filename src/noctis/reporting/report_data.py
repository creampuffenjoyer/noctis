"""Builds a single normalized ReportData structure from a workspace's cached
stage data, that every output format (JSON/Markdown/SARIF/PDF) renders from.
Keeps the four formats consistent by construction instead of each one
re-deriving findings from raw stage data independently.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from noctis.core.workspace import Workspace, WorkspaceManager
from noctis.reporting.remediation import REMEDIATION

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


@dataclass
class Finding:
    finding_id: str
    agent_type: str
    node_id: str
    severity: str
    cvss_score: float
    cvss_vector: str
    owasp_category: str
    attack_technique: str
    attack_tactic: str
    payload: str
    request: str
    response: str
    evidence: str
    remediation: str
    evidence_dir: str | None = None
    screenshot_path: str | None = None
    poc_path: str | None = None


@dataclass
class ReportData:
    workspace_id: str
    target: str
    generated_at: str
    scope_include: list[str]
    scope_exclude: list[str]
    stages_run: list[str]
    findings: list[Finding]
    discarded_count: int
    total_attempted: int

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts


def build_report_data(workspace: Workspace, workspace_manager: WorkspaceManager) -> ReportData:
    stages_run: list[str] = []
    stage_data: dict[str, Any] = {}
    for stage_name in ("recon", "graph", "risk", "planner", "exploit", "validate"):
        cached = workspace_manager.load_stage_data(workspace.id, stage_name)
        if cached is not None:
            stages_run.append(stage_name)
            stage_data[stage_name] = cached

    validate = stage_data.get("validate", {})
    raw_findings = validate.get("findings", [])
    confirmed = [f for f in raw_findings if f.get("reproduced")]

    findings = [_to_finding(f) for f in confirmed]
    findings.sort(key=lambda f: f.cvss_score, reverse=True)

    exploit = stage_data.get("exploit", {})

    return ReportData(
        workspace_id=workspace.id,
        target=workspace.target,
        generated_at=datetime.now(timezone.utc).isoformat(),
        scope_include=workspace.scope.get("include", []),
        scope_exclude=workspace.scope.get("exclude", []),
        stages_run=stages_run,
        findings=findings,
        discarded_count=len(raw_findings) - len(confirmed),
        total_attempted=exploit.get("total", 0),
    )


def _to_finding(raw: dict[str, Any]) -> Finding:
    evidence_dir = raw.get("evidence_dir")
    poc_path = str(Path(evidence_dir) / "poc.py") if evidence_dir else None
    agent_type = raw.get("agent_type", "")

    return Finding(
        finding_id=raw.get("finding_id", ""),
        agent_type=agent_type,
        node_id=raw.get("node_id", ""),
        severity=raw.get("severity") or "Info",
        cvss_score=raw.get("cvss_score") or 0.0,
        cvss_vector=raw.get("cvss_vector") or "",
        owasp_category=raw.get("owasp_category") or "",
        attack_technique=raw.get("attack_technique") or "",
        attack_tactic=raw.get("attack_tactic") or "",
        payload=raw.get("payload", ""),
        request=raw.get("request", ""),
        response=raw.get("response", ""),
        evidence=raw.get("evidence", ""),
        remediation=REMEDIATION.get(agent_type, "Review the finding manually and apply defense-in-depth controls appropriate to the vulnerability class."),
        evidence_dir=evidence_dir,
        screenshot_path=raw.get("screenshot_path"),
        poc_path=poc_path,
    )
