from noctis.config.settings import Settings
from noctis.core.workspace import WorkspaceManager
from noctis.reporting.report_data import build_report_data


def _workspace_with_stages(tmp_path):
    settings = Settings(workspace_dir=tmp_path / "workspaces", _env_file=None)
    manager = WorkspaceManager(settings)
    ws = manager.create(target="https://example.com", scope={"include": ["/api/*"], "exclude": ["/logout"]})
    manager.save_stage_data(ws.id, "recon", {"web": {}, "code": None})
    manager.save_stage_data(ws.id, "graph", {"graph": {"nodes": []}})
    manager.save_stage_data(
        ws.id,
        "exploit",
        {"total": 3, "found": 1, "findings": [{"agent_type": "sqli"}]},
    )
    manager.save_stage_data(
        ws.id,
        "validate",
        {
            "findings": [
                {
                    "finding_id": "sqli_abc123",
                    "agent_type": "sqli",
                    "node_id": "endpoint::GET::https://example.com/search?q=1",
                    "reproduced": True,
                    "severity": "Critical",
                    "cvss_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "owasp_category": "A03:2021 - Injection",
                    "attack_tactic": "TA0001 - Initial Access",
                    "attack_technique": "T1190 - Exploit Public-Facing Application",
                    "payload": "'",
                    "request": "GET https://example.com/search?q=%27",
                    "response": "HTTP 200 sql syntax error",
                    "evidence": "database error signature",
                    "evidence_dir": str(manager.path(ws.id) / "evidence" / "sqli_abc123"),
                    "screenshot_path": None,
                },
                {
                    "finding_id": "xss_def456",
                    "agent_type": "xss",
                    "node_id": "endpoint::GET::https://example.com/greet",
                    "reproduced": False,
                    "rationale": "did not reproduce on independent replay",
                },
            ],
            "confirmed": 1,
            "discarded": 1,
        },
    )
    return ws, manager


def test_build_report_data_only_includes_reproduced_findings(tmp_path):
    ws, manager = _workspace_with_stages(tmp_path)
    data = build_report_data(ws, manager)

    assert len(data.findings) == 1
    assert data.findings[0].finding_id == "sqli_abc123"
    assert data.discarded_count == 1
    assert data.total_attempted == 3


def test_build_report_data_derives_remediation_and_poc_path(tmp_path):
    ws, manager = _workspace_with_stages(tmp_path)
    data = build_report_data(ws, manager)

    finding = data.findings[0]
    assert "parameterized queries" in finding.remediation.lower()
    assert finding.poc_path.endswith("poc.py")


def test_severity_counts(tmp_path):
    ws, manager = _workspace_with_stages(tmp_path)
    data = build_report_data(ws, manager)

    counts = data.severity_counts
    assert counts["Critical"] == 1
    assert counts["High"] == 0


def test_scope_and_stages_carried_through(tmp_path):
    ws, manager = _workspace_with_stages(tmp_path)
    data = build_report_data(ws, manager)

    assert data.scope_include == ["/api/*"]
    assert data.scope_exclude == ["/logout"]
    assert "recon" in data.stages_run
    assert "validate" in data.stages_run
    assert "risk" not in data.stages_run  # never cached in this fixture


def test_no_stages_run_yields_empty_report(tmp_path):
    settings = Settings(workspace_dir=tmp_path / "workspaces", _env_file=None)
    manager = WorkspaceManager(settings)
    ws = manager.create(target="https://example.com")

    data = build_report_data(ws, manager)

    assert data.findings == []
    assert data.stages_run == []
    assert data.total_attempted == 0
