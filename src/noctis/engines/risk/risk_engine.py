"""Risk engine: scores every actionable node in the attack surface graph by
exploitability x impact, and detects multi-hop attack chains through it.

Scoring factors (per the plan): input type, authentication requirement, data
flow to dangerous sinks, stack vulnerability history (approximated here via
sink category severity, since a real CVE feed is out of scope), and HTTP
method. This is a prioritization score for the Test Planner, not a CVSS
score -- that's the Validator's job once a finding is actually confirmed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import networkx as nx

from noctis.engines.graph.attack_surface import ROOT_NODE, AttackSurfaceGraph

# Impact of reaching a given sink category, on a 0-10 scale.
SINK_IMPACT: dict[str, float] = {
    "command_exec": 10.0,
    "eval": 9.0,
    "sql": 9.0,
    "file_ops": 7.0,
    "render": 6.0,
}
DEFAULT_IMPACT = 2.0  # a bare endpoint with no traced sink still has some impact
SECRET_IMPACT = 8.0

METHOD_EXPLOITABILITY: dict[str, float] = {
    "GET": 4.0,
    "POST": 7.0,
    "PUT": 6.0,
    "DELETE": 6.0,
    "PATCH": 6.0,
    "ANY": 5.0,
}
BASE_EXPLOITABILITY = 3.0
UNAUTH_BONUS = 3.0
INPUT_BONUS_PER_PARAM = 0.6
MAX_INPUT_BONUS = 3.0

SCORABLE_TYPES = {"endpoint", "form", "js_route", "secret"}


@dataclass
class NodeRiskScore:
    node_id: str
    node_type: str
    exploitability: float
    impact: float
    score: float
    factors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "exploitability": self.exploitability,
            "impact": self.impact,
            "score": self.score,
            "factors": self.factors,
        }


@dataclass
class AttackChain:
    path: list[str]
    score: float

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "score": self.score}


class RiskEngine:
    def score_graph(self, asg: AttackSurfaceGraph) -> list[NodeRiskScore]:
        g = asg.graph
        scores = [
            self._score_node(g, node_id, data)
            for node_id, data in g.nodes(data=True)
            if data.get("type") in SCORABLE_TYPES
        ]
        scores.sort(key=lambda s: s.score, reverse=True)
        return scores

    def detect_chains(
        self, asg: AttackSurfaceGraph, scores: list[NodeRiskScore], max_chains: int = 25
    ) -> list[AttackChain]:
        g = asg.graph
        score_by_node = {s.node_id: s.score for s in scores}
        sink_and_secret_nodes = [n for n, d in g.nodes(data=True) if d.get("type") in ("sink", "secret")]

        chains: list[AttackChain] = []
        if not g.has_node(ROOT_NODE):
            return chains

        for target in sink_and_secret_nodes:
            try:
                paths = list(nx.all_simple_paths(g, ROOT_NODE, target, cutoff=6))
            except (nx.NodeNotFound, nx.NetworkXNoPath):
                continue
            for path in paths:
                path_score = sum(score_by_node.get(n, 0.0) for n in path)
                chains.append(AttackChain(path=path, score=round(path_score, 2)))

        chains.sort(key=lambda c: c.score, reverse=True)
        return chains[:max_chains]

    def _score_node(self, g: nx.DiGraph, node_id: str, data: dict[str, Any]) -> NodeRiskScore:
        node_type = data["type"]
        factors: list[str] = []

        if node_type == "secret":
            factors.append(f"hardcoded secret ({data.get('kind', 'unknown')})")
            return NodeRiskScore(
                node_id=node_id,
                node_type=node_type,
                exploitability=10.0,
                impact=SECRET_IMPACT,
                score=round(10.0 * SECRET_IMPACT / 10, 2),
                factors=factors,
            )

        exploitability = BASE_EXPLOITABILITY
        method = data.get("method", "GET")
        method_bonus = METHOD_EXPLOITABILITY.get(method, METHOD_EXPLOITABILITY["ANY"])
        exploitability += method_bonus
        factors.append(f"{method} method (+{method_bonus:.1f})")

        if not data.get("auth_required", False):
            exploitability += UNAUTH_BONUS
            factors.append(f"unauthenticated (+{UNAUTH_BONUS:.1f})")

        inputs = data.get("inputs", [])
        if inputs:
            input_bonus = min(len(inputs) * INPUT_BONUS_PER_PARAM, MAX_INPUT_BONUS)
            exploitability += input_bonus
            factors.append(f"{len(inputs)} input param(s) (+{input_bonus:.1f})")

        exploitability = min(exploitability, 10.0)

        impact, impact_factor = self._reachable_impact(g, node_id)
        factors.append(impact_factor)

        score = round(exploitability * impact / 10, 2)
        return NodeRiskScore(
            node_id=node_id,
            node_type=node_type,
            exploitability=round(exploitability, 2),
            impact=impact,
            score=score,
            factors=factors,
        )

    @staticmethod
    def _reachable_impact(g: nx.DiGraph, node_id: str) -> tuple[float, str]:
        """Impact = the worst sink/secret this node can reach in the graph."""
        best_impact = DEFAULT_IMPACT
        best_reason = "no traced sink (baseline)"

        try:
            descendants = nx.descendants(g, node_id)
        except nx.NetworkXError:
            return best_impact, best_reason

        for descendant in descendants:
            desc_data = g.nodes[descendant]
            if desc_data.get("type") == "sink":
                sink_impact = SINK_IMPACT.get(desc_data.get("category", ""), DEFAULT_IMPACT)
                if sink_impact > best_impact:
                    best_impact = sink_impact
                    best_reason = f"reaches {desc_data.get('category')} sink"
            elif desc_data.get("type") == "secret" and SECRET_IMPACT > best_impact:
                best_impact = SECRET_IMPACT
                best_reason = "reaches hardcoded secret"

        return best_impact, best_reason
