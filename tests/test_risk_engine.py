from noctis.engines.graph.attack_surface import build_attack_surface_graph
from noctis.engines.risk.risk_engine import RiskEngine

SAMPLE_RECON = {
    "web": {
        "endpoints": [{"url": "https://example.com/login", "method": "POST", "source": "form"}],
        "forms": [],
        "js_routes": [],
        "fingerprint": {},
    },
    "code": {
        "routes": [{"method": "POST", "path": "/login", "file": "app.py", "line": 10, "framework": "flask"}],
        "sinks": [{"file": "app.py", "line": 12, "category": "sql", "snippet": "cursor.execute(q)"}],
        "secrets": [{"file": "app.py", "line": 3, "kind": "generic_api_key", "masked_value": "abcd****wxyz"}],
    },
}


def _build_scores():
    asg = build_attack_surface_graph(SAMPLE_RECON)
    return asg, RiskEngine().score_graph(asg)


def test_endpoint_reaching_sql_sink_has_high_impact():
    _, scores = _build_scores()
    endpoint_score = next(s for s in scores if s.node_type == "endpoint")
    assert endpoint_score.impact == 9.0
    assert endpoint_score.score > 5.0


def test_secret_node_scores_high_regardless_of_reachability():
    _, scores = _build_scores()
    secret_score = next(s for s in scores if s.node_type == "secret")
    assert secret_score.exploitability == 10.0
    assert secret_score.impact == 8.0


def test_scores_sorted_descending():
    _, scores = _build_scores()
    assert scores == sorted(scores, key=lambda s: s.score, reverse=True)


def test_chain_detector_finds_root_to_sink_path():
    asg, scores = _build_scores()
    chains = RiskEngine().detect_chains(asg, scores)
    assert chains
    assert all(chain.path[0] == "target::root" for chain in chains)
    assert any(any("sink" in node for node in chain.path) for chain in chains)
