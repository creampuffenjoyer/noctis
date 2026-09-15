import json

from noctis.reporting import json_generator, markdown_generator, pdf_generator, sarif_generator
from noctis.reporting.report_data import Finding, ReportData


def _sample_data(tmp_path, with_screenshot=False) -> ReportData:
    evidence_dir = tmp_path / "evidence" / "sqli_abc123"
    evidence_dir.mkdir(parents=True)

    screenshot_path = None
    if with_screenshot:
        import struct
        import zlib

        # minimal 1x1 white PNG, hand-built to avoid a Pillow dependency
        def _chunk(tag, data):
            return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))

        raw = b"\x00\xff\xff\xff"
        png = (
            b"\x89PNG\r\n\x1a\n"
            + _chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + _chunk(b"IDAT", zlib.compress(raw))
            + _chunk(b"IEND", b"")
        )
        screenshot_path = str(evidence_dir / "screenshot.png")
        with open(screenshot_path, "wb") as f:
            f.write(png)

    finding = Finding(
        finding_id="sqli_abc123",
        agent_type="sqli",
        node_id="endpoint::GET::https://example.com/search?q=1",
        severity="Critical",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        owasp_category="A03:2021 - Injection",
        attack_technique="T1190 - Exploit Public-Facing Application",
        attack_tactic="TA0001 - Initial Access",
        payload="'",
        request="GET https://example.com/search?q=%27",
        response="HTTP 200 sql syntax error",
        evidence="database error signature 'sql syntax' returned",
        remediation="Use parameterized queries.",
        evidence_dir=str(evidence_dir),
        screenshot_path=screenshot_path,
        poc_path=str(evidence_dir / "poc.py"),
    )
    return ReportData(
        workspace_id="ws123",
        target="https://example.com",
        generated_at="2026-01-01T00:00:00+00:00",
        scope_include=["/api/*"],
        scope_exclude=[],
        stages_run=["recon", "graph", "risk", "planner", "exploit", "validate"],
        findings=[finding],
        discarded_count=1,
        total_attempted=3,
    )


def test_json_generator_writes_valid_json(tmp_path):
    data = _sample_data(tmp_path)
    path = json_generator.generate(data, tmp_path / "reports")

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["target"] == "https://example.com"
    assert payload["findings"][0]["finding_id"] == "sqli_abc123"
    assert payload["severity_counts"]["Critical"] == 1


def test_markdown_generator_includes_finding_details(tmp_path):
    data = _sample_data(tmp_path)
    path = markdown_generator.generate(data, tmp_path / "reports")

    text = path.read_text(encoding="utf-8")
    assert "# Noctis Security Assessment Report" in text
    assert "sqli_abc123" in text
    assert "CVSS:3.1/AV:N" in text
    assert "Use parameterized queries." in text


def test_sarif_generator_produces_valid_structure(tmp_path):
    data = _sample_data(tmp_path)
    path = sarif_generator.generate(data, tmp_path / "reports")

    sarif = json.loads(path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Noctis"
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert "sqli" in rule_ids
    result = run["results"][0]
    assert result["ruleId"] == "sqli"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("https://")
    assert result["properties"]["cvss_score"] == 9.8
    assert result["webRequest"]["method"] == "GET"


def test_sarif_generator_uses_file_location_for_credential_exposure(tmp_path):
    data = _sample_data(tmp_path)
    data.findings[0].agent_type = "credential_exposure"
    data.findings[0].request = "static analysis: config.py:5"
    data.findings[0].node_id = "secret::config.py::5"

    path = sarif_generator.generate(data, tmp_path / "reports")
    sarif = json.loads(path.read_text(encoding="utf-8"))
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "config.py"


def test_pdf_generator_produces_a_pdf_file(tmp_path):
    data = _sample_data(tmp_path, with_screenshot=True)
    path = pdf_generator.generate(data, tmp_path / "reports")

    assert path.exists()
    header = path.read_bytes()[:5]
    assert header == b"%PDF-"


def test_pdf_generator_handles_no_findings(tmp_path):
    data = _sample_data(tmp_path)
    data.findings = []
    path = pdf_generator.generate(data, tmp_path / "reports")

    assert path.exists()
    assert path.read_bytes()[:5] == b"%PDF-"
