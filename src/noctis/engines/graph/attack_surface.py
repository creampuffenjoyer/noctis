"""Attack surface graph: combines web recon + code analysis into a single NetworkX
graph. Nodes are endpoints/forms/routes/sinks/secrets; edges are data flow and
trust-boundary relationships. This graph is what the Risk Engine (Phase 3) scores.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import networkx as nx

ROOT_NODE = "target::root"


@dataclass
class AttackSurfaceGraph:
    graph: nx.DiGraph

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for _, data in self.graph.nodes(data=True):
            node_type = data.get("type", "unknown")
            counts[node_type] = counts.get(node_type, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "graph": nx.node_link_data(self.graph, edges="edges"),
            "summary": self.summary(),
            "node_count": self.graph.number_of_nodes(),
            "edge_count": self.graph.number_of_edges(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttackSurfaceGraph":
        return cls(graph=nx.node_link_graph(data["graph"], edges="edges"))


def build_attack_surface_graph(recon_result: dict[str, Any]) -> AttackSurfaceGraph:
    g = nx.DiGraph()
    g.add_node(ROOT_NODE, type="root")

    web = recon_result.get("web") or {}
    code = recon_result.get("code") or None

    _add_web_nodes(g, web)
    if code:
        _add_code_nodes(g, code)
        _link_routes_to_endpoints(g, web, code)

    return AttackSurfaceGraph(graph=g)


def _add_web_nodes(g: nx.DiGraph, web: dict[str, Any]) -> None:
    for endpoint in web.get("endpoints", []):
        node_id = f"endpoint::{endpoint['method']}::{endpoint['url']}"
        g.add_node(
            node_id,
            type="endpoint",
            method=endpoint["method"],
            url=endpoint["url"],
            source=endpoint.get("source", "crawl"),
            auth_required=False,
        )
        g.add_edge(ROOT_NODE, node_id, relation="discovered")

    for form in web.get("forms", []):
        node_id = f"form::{form['action']}"
        g.add_node(
            node_id,
            type="form",
            page_url=form["page_url"],
            action=form["action"],
            method=form["method"],
            inputs=form.get("inputs", []),
        )
        page_node = next((n for n in g.nodes if g.nodes[n].get("url") == form["page_url"]), ROOT_NODE)
        g.add_edge(page_node, node_id, relation="submits_to")

    for route in web.get("js_routes", []):
        node_id = f"js_route::{route}"
        g.add_node(node_id, type="js_route", path=route)
        g.add_edge(ROOT_NODE, node_id, relation="referenced_in_js")


def _add_code_nodes(g: nx.DiGraph, code: dict[str, Any]) -> None:
    for route in code.get("routes", []):
        node_id = f"route::{route['method']}::{route['path']}"
        g.add_node(
            node_id,
            type="route",
            method=route["method"],
            path=route["path"],
            file=route["file"],
            line=route["line"],
            framework=route["framework"],
        )

    for sink in code.get("sinks", []):
        node_id = f"sink::{sink['file']}::{sink['line']}::{sink['category']}"
        g.add_node(
            node_id,
            type="sink",
            category=sink["category"],
            file=sink["file"],
            line=sink["line"],
            snippet=sink["snippet"],
        )
        # naive same-file heuristic: connect any route defined in the same file to this sink
        for route in code.get("routes", []):
            if route["file"] == sink["file"]:
                route_node = f"route::{route['method']}::{route['path']}"
                if g.has_node(route_node):
                    g.add_edge(route_node, node_id, relation="flows_to_sink")

    for secret in code.get("secrets", []):
        node_id = f"secret::{secret['file']}::{secret['line']}"
        g.add_node(
            node_id,
            type="secret",
            kind=secret["kind"],
            file=secret["file"],
            line=secret["line"],
            masked_value=secret["masked_value"],
        )


def _link_routes_to_endpoints(g: nx.DiGraph, web: dict[str, Any], code: dict[str, Any]) -> None:
    """Connect live web endpoints to their matching source-code route, when the
    URL path matches a discovered route pattern (converting Flask/Express-style
    `<param>`/`:param`/`{param}` placeholders to a wildcard first).
    """
    route_nodes = [n for n, d in g.nodes(data=True) if d.get("type") == "route"]

    for endpoint in web.get("endpoints", []):
        endpoint_path = urlparse(endpoint["url"]).path or "/"
        endpoint_node = f"endpoint::{endpoint['method']}::{endpoint['url']}"
        for route_node in route_nodes:
            route_path = g.nodes[route_node]["path"]
            if _paths_match(endpoint_path, route_path):
                g.add_edge(endpoint_node, route_node, relation="maps_to_source")


def _paths_match(url_path: str, route_path: str) -> bool:
    import re

    pattern = re.sub(r"(<[^>]+>|:[a-zA-Z_]+|\{[^}]+\})", "[^/]+", route_path)
    pattern = f"^{pattern}$"
    try:
        return bool(re.match(pattern, url_path))
    except re.error:
        return url_path == route_path
