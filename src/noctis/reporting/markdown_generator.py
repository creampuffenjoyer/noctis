"""Markdown report: mirrors the PDF's structure (cover info, executive
summary, scope/methodology, findings table, detailed findings, appendix)
in a clean, GitHub-friendly document.
"""
from __future__ import annotations

from pathlib import Path

from noctis.reporting.report_data import SEVERITY_ORDER, ReportData

SEVERITY_BADGE = {
    "Critical": "**CRITICAL**",
    "High": "**HIGH**",
    "Medium": "MEDIUM",
    "Low": "LOW",
    "Info": "INFO",
}


def generate(data: ReportData, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "report.md"
    path.write_text(_render(data), encoding="utf-8")
    return path


def _render(data: ReportData) -> str:
    lines: list[str] = []

    lines.append("# Noctis Security Assessment Report")
    lines.append("")
    lines.append(f"**Target:** {data.target}  ")
    lines.append(f"**Generated:** {data.generated_at}  ")
    lines.append(f"**Workspace:** `{data.workspace_id}`")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")
    counts = data.severity_counts
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for severity in SEVERITY_ORDER:
        if counts.get(severity):
            lines.append(f"| {SEVERITY_BADGE[severity]} | {counts[severity]} |")
    lines.append("")
    lines.append(
        f"{len(data.findings)} finding(s) confirmed via independent replay out of {data.total_attempted} "
        f"exploitation attempt(s); {data.discarded_count} candidate(s) did not reproduce and were discarded."
    )
    lines.append("")

    lines.append("## Scope & Methodology")
    lines.append("")
    lines.append(f"- **Include patterns:** {', '.join(data.scope_include) or '(all in-scope)'}")
    lines.append(f"- **Exclude patterns:** {', '.join(data.scope_exclude) or '(none)'}")
    lines.append(f"- **Stages run:** {' -> '.join(data.stages_run)}")
    lines.append("")

    if data.findings:
        lines.append("## Findings Summary")
        lines.append("")
        lines.append("| Severity | CVSS | Type | OWASP | Finding ID |")
        lines.append("|---|---|---|---|---|")
        for f in data.findings:
            lines.append(
                f"| {SEVERITY_BADGE.get(f.severity, f.severity)} | {f.cvss_score:.1f} | {f.agent_type} "
                f"| {f.owasp_category} | `{f.finding_id}` |"
            )
        lines.append("")

        lines.append("## Detailed Findings")
        lines.append("")
        for f in data.findings:
            lines.append(f"### {SEVERITY_BADGE.get(f.severity, f.severity)} - {f.agent_type} (`{f.finding_id}`)")
            lines.append("")
            lines.append(f"- **CVSS:** {f.cvss_score:.1f} ({f.cvss_vector})")
            lines.append(f"- **OWASP:** {f.owasp_category}")
            lines.append(f"- **MITRE ATT&CK:** {f.attack_tactic} / {f.attack_technique}")
            lines.append(f"- **Node:** `{f.node_id}`")
            lines.append("")
            lines.append(f"**Evidence:** {f.evidence}")
            lines.append("")
            lines.append(f"**Payload:** `{f.payload}`")
            lines.append("")
            lines.append("**Request:**")
            lines.append("```")
            lines.append(f.request)
            lines.append("```")
            lines.append("")
            lines.append("**Response:**")
            lines.append("```")
            lines.append(f.response)
            lines.append("```")
            lines.append("")
            if f.screenshot_path:
                lines.append(f"**Screenshot:** `{f.screenshot_path}`")
                lines.append("")
            if f.poc_path:
                lines.append(f"**PoC script:** `{f.poc_path}`")
                lines.append("")
            lines.append(f"**Remediation:** {f.remediation}")
            lines.append("")
    else:
        lines.append("## Findings")
        lines.append("")
        lines.append("No findings were confirmed during this scan.")
        lines.append("")

    return "\n".join(lines) + "\n"
