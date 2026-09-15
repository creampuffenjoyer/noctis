from noctis.engines.graph.attack_surface import build_attack_surface_graph


def test_graph_includes_root_and_endpoints():
    recon = {
        "web": {
            "endpoints": [{"url": "https://example.com/", "method": "GET", "source": "crawl"}],
            "forms": [],
            "js_routes": [],
            "fingerprint": {},
        },
        "code": None,
    }
    result = build_attack_surface_graph(recon).to_dict()
    assert result["summary"]["root"] == 1
    assert result["summary"]["endpoint"] == 1


def test_route_links_to_sink_in_same_file():
    recon = {
        "web": {"endpoints": [], "forms": [], "js_routes": [], "fingerprint": {}},
        "code": {
            "routes": [{"method": "GET", "path": "/login", "file": "app.py", "line": 10, "framework": "flask"}],
            "sinks": [{"file": "app.py", "line": 12, "category": "sql", "snippet": "cursor.execute(q)"}],
            "secrets": [],
        },
    }
    graph = build_attack_surface_graph(recon)
    route_node = "route::GET::/login"
    sink_node = "sink::app.py::12::sql"
    assert graph.graph.has_edge(route_node, sink_node)


def test_endpoint_maps_to_parameterized_route():
    recon = {
        "web": {
            "endpoints": [{"url": "https://example.com/users/42", "method": "GET", "source": "crawl"}],
            "forms": [],
            "js_routes": [],
            "fingerprint": {},
        },
        "code": {
            "routes": [{"method": "GET", "path": "/users/<id>", "file": "app.py", "line": 5, "framework": "flask"}],
            "sinks": [],
            "secrets": [],
        },
    }
    graph = build_attack_surface_graph(recon)
    endpoint_node = "endpoint::GET::https://example.com/users/42"
    route_node = "route::GET::/users/<id>"
    assert graph.graph.has_edge(endpoint_node, route_node)
