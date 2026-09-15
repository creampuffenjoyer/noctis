"""SARIF 2.1.0 report: the standard format for CI/CD pipelines (GitHub code
scanning, GitLab, etc). Each finding becomes one result; locations use the
target URL as the artifact for HTTP-based findings, or the actual source
file/line for credential_exposure findings from static analysis. Also
attaches SARIF's webRequest object for HTTP-based findings, which is the
spec's purpose-built way to describe a DAST tool's request, rather than
forcing it into a fake file location.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from noctis.reporting.report_data import ReportData

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SEVERITY_TO_LEVEL = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Info": "note"}


def generate(data: ReportData, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "report.sarif"

    rules = _build_rules(data)
    results = [_build_result(f) for f in data.findings]

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Noctis",
                        "informationUri": "https://github.com/creampuffenjoyer/noctis",
                        "version": "0.1.0",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return path


def _build_rules(data: ReportData) -> list[dict]:
    seen: dict[str, dict] = {}
    for f in data.findings:
        if f.agent_type in seen:
            continue
        seen[f.agent_type] = {
            "id": f.agent_type,
            "name": f.agent_type,
            "shortDescription": {"text": f.owasp_category or f.agent_type},
            "fullDescription": {"text": f.remediation},
            "properties": {"tags": ["security", f.owasp_category, f.attack_technique]},
            "defaultConfiguration": {"level": SEVERITY_TO_LEVEL.get(f.severity, "warning")},
        }
    return list(seen.values())


def _build_result(f) -> dict:
    is_file_based = f.agent_type == "credential_exposure"

    if is_file_based:
        # node_id for secrets is not a file path; the file/line live in the
        # finding's request text ("static analysis: {file}:{line}") captured
        # by the credential_exposure agent -- fall back to node_id if unparsable.
        location_uri = f.node_id
        try:
            location_uri = f.request.split("static analysis: ", 1)[1].rsplit(":", 1)[0]
        except IndexError:
            pass
        location = {"physicalLocation": {"artifactLocation": {"uri": location_uri}}}
    else:
        url = _extract_url(f.node_id) or f.node_id
        location = {"physicalLocation": {"artifactLocation": {"uri": url}}}

    result: dict = {
        "ruleId": f.agent_type,
        "level": SEVERITY_TO_LEVEL.get(f.severity, "warning"),
        "message": {"text": f.evidence or f.remediation},
        "locations": [location],
        "properties": {
            "finding_id": f.finding_id,
            "severity": f.severity,
            "cvss_score": f.cvss_score,
            "cvss_vector": f.cvss_vector,
            "owasp_category": f.owasp_category,
            "attack_tactic": f.attack_tactic,
            "attack_technique": f.attack_technique,
        },
    }

    if not is_file_based and f.request:
        method = f.request.split(" ", 1)[0] if f.request else "GET"
        target = _extract_url(f.node_id) or f.node_id
        result["webRequest"] = {"protocol": "http", "method": method, "target": target}

    return result


def _extract_url(node_id: str) -> str | None:
    for part in node_id.split("::"):
        parsed = urlparse(part)
        if parsed.scheme in ("http", "https"):
            return part
    return None
