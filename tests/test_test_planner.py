import asyncio

from noctis.engines.graph.attack_surface import build_attack_surface_graph
from noctis.engines.planner.test_planner import ConcurrencyManager, TestPlanner
from noctis.engines.risk.risk_engine import RiskEngine


def test_sql_sink_maps_to_sqli_agent():
    recon = {
        "web": {
            "endpoints": [{"url": "https://example.com/search", "method": "GET", "source": "crawl"}],
            "forms": [],
            "js_routes": [],
            "fingerprint": {},
        },
        "code": {
            "routes": [{"method": "GET", "path": "/search", "file": "app.py", "line": 1, "framework": "flask"}],
            "sinks": [{"file": "app.py", "line": 5, "category": "sql", "snippet": "execute(q)"}],
            "secrets": [],
        },
    }
    asg = build_attack_surface_graph(recon)
    scores = RiskEngine().score_graph(asg)
    queue = TestPlanner().build_queue(asg, scores)

    endpoint_tasks = [t for t in queue if t.node_type == "endpoint"]
    assert any(t.agent_type == "sqli" for t in endpoint_tasks)


def test_login_form_maps_to_auth_agent():
    recon = {
        "web": {
            "endpoints": [{"url": "https://example.com/login", "method": "POST", "source": "form"}],
            "forms": [
                {
                    "page_url": "https://example.com/",
                    "action": "https://example.com/login",
                    "method": "POST",
                    "inputs": ["username", "password"],
                }
            ],
            "js_routes": [],
            "fingerprint": {},
        },
        "code": None,
    }
    asg = build_attack_surface_graph(recon)
    scores = RiskEngine().score_graph(asg)
    queue = TestPlanner().build_queue(asg, scores)

    form_tasks = [t for t in queue if t.node_type == "form"]
    assert any(t.agent_type == "auth" for t in form_tasks)


def test_secret_maps_to_credential_exposure():
    recon = {
        "web": {"endpoints": [], "forms": [], "js_routes": [], "fingerprint": {}},
        "code": {
            "routes": [],
            "sinks": [],
            "secrets": [{"file": "config.py", "line": 2, "kind": "aws_access_key", "masked_value": "AKIA****WXYZ"}],
        },
    }
    asg = build_attack_surface_graph(recon)
    scores = RiskEngine().score_graph(asg)
    queue = TestPlanner().build_queue(asg, scores)

    assert any(t.agent_type == "credential_exposure" for t in queue)


def test_concurrency_manager_respects_max_workers():
    async def scenario():
        manager = ConcurrencyManager(max_workers=2)
        active = 0
        peak = 0

        async def runner(task: int) -> int:
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1
            return task * 2

        results = await manager.run_tasks([1, 2, 3, 4, 5], runner)
        return results, peak

    results, peak = asyncio.run(scenario())
    assert results == [2, 4, 6, 8, 10]
    assert peak <= 2
