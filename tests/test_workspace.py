from noctis.config.settings import Settings
from noctis.core.workspace import WorkspaceManager, WorkspaceNotFoundError

import pytest


@pytest.fixture
def manager(tmp_path):
    settings = Settings(workspace_dir=tmp_path / "workspaces", _env_file=None)
    return WorkspaceManager(settings)


def test_create_and_get_roundtrip(manager):
    ws = manager.create(target="https://example.com")
    fetched = manager.get(ws.id)
    assert fetched.target == "https://example.com"
    assert fetched.status == "created"


def test_get_missing_workspace_raises(manager):
    with pytest.raises(WorkspaceNotFoundError):
        manager.get("does-not-exist")


def test_list_orders_newest_first(manager):
    first = manager.create(target="https://a.com")
    second = manager.create(target="https://b.com")
    ids = [ws.id for ws in manager.list()]
    assert ids.index(second.id) < ids.index(first.id)


def test_update_status_and_stage(manager):
    ws = manager.create(target="https://example.com")
    manager.update_status(ws.id, "running", stage="recon")
    fetched = manager.get(ws.id)
    assert fetched.status == "running"
    assert fetched.stage == "recon"


def test_stage_data_roundtrip(manager):
    ws = manager.create(target="https://example.com")
    manager.save_stage_data(ws.id, "recon", {"endpoints": ["a", "b"]})
    assert manager.load_stage_data(ws.id, "recon") == {"endpoints": ["a", "b"]}
    assert manager.load_stage_data(ws.id, "graph") is None
