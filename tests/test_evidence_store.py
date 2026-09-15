from noctis.config.settings import Settings
from noctis.core.workspace import WorkspaceManager
from noctis.evidence.store import EvidenceStore, compute_finding_id


def test_finding_id_is_deterministic():
    a = compute_finding_id("sqli", "endpoint::GET::https://example.com/search?q=1")
    b = compute_finding_id("sqli", "endpoint::GET::https://example.com/search?q=1")
    c = compute_finding_id("xss", "endpoint::GET::https://example.com/search?q=1")
    assert a == b
    assert a != c


def test_saves_request_response_and_poc(tmp_path):
    settings = Settings(workspace_dir=tmp_path / "workspaces", _env_file=None)
    manager = WorkspaceManager(settings)
    ws = manager.create(target="https://example.com")
    store = EvidenceStore(manager, ws.id)

    finding_id = "sqli_abc123"
    rr_path = store.save_request_response(finding_id, "GET /search?q='", "HTTP 500 error")
    poc_path = store.save_poc_script(finding_id, "print('poc')")

    assert "REQUEST" in open(rr_path, encoding="utf-8").read()
    assert "poc" in open(poc_path, encoding="utf-8").read()
    assert manager.path(ws.id) / "evidence" / finding_id == store.finding_dir(finding_id)


def test_saves_screenshot_bytes(tmp_path):
    settings = Settings(workspace_dir=tmp_path / "workspaces", _env_file=None)
    manager = WorkspaceManager(settings)
    ws = manager.create(target="https://example.com")
    store = EvidenceStore(manager, ws.id)

    path = store.save_screenshot("xss_def456", b"\x89PNG\r\n\x1a\n fake")
    with open(path, "rb") as f:
        assert f.read().startswith(b"\x89PNG")
