import httpx
import pytest

from noctis.config.settings import Settings
from noctis.core.model_router import ModelRouter
from noctis.core.scope import ScopeEngine
from noctis.core.workspace import WorkspaceManager
from noctis.evidence.store import compute_finding_id
from noctis.validator.validator import Validator

NODE_ID = "endpoint::GET::https://example.com/search?q=test"


def _setup(tmp_path):
    settings = Settings(workspace_dir=tmp_path / "workspaces", requests_per_second=0, _env_file=None)
    manager = WorkspaceManager(settings)
    ws = manager.create(target="https://example.com")
    scope = ScopeEngine(target="https://example.com")
    validator = Validator(
        workspace_manager=manager,
        workspace_id=ws.id,
        scope=scope,
        settings=settings,
        model_router=ModelRouter(settings),
    )
    return validator, manager, ws


def _graph_result():
    return {
        "graph": {
            "nodes": [
                {
                    "id": NODE_ID,
                    "type": "endpoint",
                    "method": "GET",
                    "url": "https://example.com/search?q=test",
                    "inputs": ["q"],
                }
            ]
        }
    }


def _exploit_result():
    return {
        "findings": [
            {
                "node_id": NODE_ID,
                "node_type": "endpoint",
                "agent_type": "sqli",
                "priority_score": 5.0,
                "rationale": "generic candidate",
                "result": {"found": True, "payload": "'"},
                "error": None,
            }
        ]
    }


@pytest.mark.asyncio
async def test_reproducing_finding_gets_scored_and_evidence_saved(tmp_path, httpx_mock):
    def responder(request: httpx.Request) -> httpx.Response:
        if "%27" in str(request.url):
            return httpx.Response(200, text="You have an error in your SQL syntax near '''")
        return httpx.Response(200, text="normal results")

    httpx_mock.add_callback(responder, is_reusable=True)
    validator, manager, ws = _setup(tmp_path)

    result = await validator.validate_findings(_exploit_result(), _graph_result(), repo_path=None)

    assert result["confirmed"] == 1
    assert result["discarded"] == 0
    finding = result["findings"][0]
    assert finding["reproduced"] is True
    assert finding["severity"] in ("Critical", "High")
    assert finding["cvss_score"] > 0
    assert finding["owasp_category"].startswith("A03:2021")
    assert "T1190" in finding["attack_technique"]
    assert finding["cve_refs"] == []

    finding_id = compute_finding_id("sqli", NODE_ID)
    evidence_dir = manager.path(ws.id) / "evidence" / finding_id
    assert (evidence_dir / "request_response.txt").exists()
    assert (evidence_dir / "poc.py").exists()


@pytest.mark.asyncio
async def test_non_reproducing_finding_is_discarded_not_silently_dropped(tmp_path, httpx_mock):
    httpx_mock.add_response(text="totally normal page, no errors ever", is_reusable=True)
    validator, manager, ws = _setup(tmp_path)

    result = await validator.validate_findings(_exploit_result(), _graph_result(), repo_path=None)

    assert result["confirmed"] == 0
    assert result["discarded"] == 1
    finding = result["findings"][0]
    assert finding["reproduced"] is False
    assert finding["cvss_score"] is None
    assert "did not reproduce" in finding["rationale"]


@pytest.mark.asyncio
async def test_unknown_agent_type_is_discarded_gracefully(tmp_path):
    validator, manager, ws = _setup(tmp_path)
    exploit_result = {
        "findings": [
            {"node_id": NODE_ID, "node_type": "endpoint", "agent_type": "not_a_real_agent", "rationale": "x", "result": {"found": True}}
        ]
    }

    result = await validator.validate_findings(exploit_result, _graph_result(), repo_path=None)

    assert result["confirmed"] == 0
    assert result["discarded"] == 1
    assert "unavailable" in result["findings"][0]["rationale"]
