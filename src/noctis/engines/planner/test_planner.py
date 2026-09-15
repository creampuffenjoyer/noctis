"""Test planner: turns the scored attack surface graph into a prioritized
exploitation queue, assigning a candidate exploitation agent type to each
node. Also provides the concurrency manager that will run those agents in
parallel once Phase 4 builds them.

Agent type assignment is heuristic: a traced dangerous sink gives a direct,
high-confidence mapping (e.g. a `sql` sink -> the `sqli` agent); everything
else falls back to parameter-name and path heuristics common in red team
recon (login-looking forms -> `auth`, URL-shaped params -> `ssrf`, etc).
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, TypeVar

import networkx as nx

from noctis.engines.graph.attack_surface import AttackSurfaceGraph
from noctis.engines.risk.risk_engine import NodeRiskScore

AGENT_TYPE_BY_SINK_CATEGORY: dict[str, str] = {
    "sql": "sqli",
    "command_exec": "rce",
    "eval": "rce",
    "file_ops": "lfi",
    "render": "xss",
}

AUTH_PATH_HINTS = ("login", "signin", "sign-in", "auth", "sso", "logon")
AUTH_INPUT_HINTS = ("password", "passwd", "pwd", "username", "email", "otp", "token")
SSRF_INPUT_HINTS = ("url", "uri", "link", "redirect", "callback", "webhook", "target", "dest", "endpoint")
IDOR_PATH_HINTS = tuple("0123456789")

GENERIC_PARAM_AGENTS = ("sqli", "xss", "idor")


@dataclass
class TestTask:
    node_id: str
    node_type: str
    agent_type: str
    priority_score: float
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "agent_type": self.agent_type,
            "priority_score": self.priority_score,
            "rationale": self.rationale,
        }


class TestPlanner:
    def build_queue(self, asg: AttackSurfaceGraph, scores: list[NodeRiskScore]) -> list[TestTask]:
        g = asg.graph
        tasks: list[TestTask] = []

        for score in scores:
            data = g.nodes[score.node_id]
            node_type = data["type"]

            if node_type == "secret":
                tasks.append(
                    TestTask(
                        node_id=score.node_id,
                        node_type=node_type,
                        agent_type="credential_exposure",
                        priority_score=score.score,
                        rationale="hardcoded secret found in source, needs validation not exploitation",
                    )
                )
                continue

            sink_categories = self._reachable_sink_categories(g, score.node_id)
            agent_types = {AGENT_TYPE_BY_SINK_CATEGORY[c] for c in sink_categories if c in AGENT_TYPE_BY_SINK_CATEGORY}

            if not agent_types:
                agent_types = self._heuristic_agent_types(data)

            for agent_type in sorted(agent_types):
                tasks.append(
                    TestTask(
                        node_id=score.node_id,
                        node_type=node_type,
                        agent_type=agent_type,
                        priority_score=score.score,
                        rationale=self._rationale_for(agent_type, sink_categories, data),
                    )
                )

        tasks.sort(key=lambda t: t.priority_score, reverse=True)
        return tasks

    @staticmethod
    def _reachable_sink_categories(g: nx.DiGraph, node_id: str) -> set[str]:
        try:
            descendants = nx.descendants(g, node_id)
        except nx.NetworkXError:
            return set()
        return {
            g.nodes[d]["category"]
            for d in descendants
            if g.nodes[d].get("type") == "sink" and "category" in g.nodes[d]
        }

    @staticmethod
    def _heuristic_agent_types(data: dict[str, Any]) -> set[str]:
        path = (data.get("url") or data.get("action") or data.get("path") or "").lower()
        inputs = [str(i).lower() for i in data.get("inputs", [])]

        if any(hint in path for hint in AUTH_PATH_HINTS) or any(
            any(hint in i for hint in AUTH_INPUT_HINTS) for i in inputs
        ):
            return {"auth"}

        if any(any(hint in i for hint in SSRF_INPUT_HINTS) for i in inputs):
            return {"ssrf"}

        agent_types: set[str] = set()
        if inputs:
            agent_types.update(GENERIC_PARAM_AGENTS)
        elif any(segment.strip("/").isdigit() for segment in path.split("/")):
            agent_types.add("idor")

        return agent_types

    @staticmethod
    def _rationale_for(agent_type: str, sink_categories: set[str], data: dict[str, Any]) -> str:
        if sink_categories:
            matched = ", ".join(sorted(sink_categories))
            return f"reaches traced {matched} sink"
        if agent_type == "auth":
            return "login-shaped endpoint or credential-looking input"
        if agent_type == "ssrf":
            return "input parameter looks URL-shaped"
        if agent_type == "idor":
            return "numeric identifier in path or no other candidate class"
        return "parameterized endpoint, no traced sink -- generic candidate"


T = TypeVar("T")
R = TypeVar("R")


class ConcurrencyManager:
    """Runs a batch of agent tasks with at most `max_workers` in flight at once."""

    def __init__(self, max_workers: int):
        self.max_workers = max(1, max_workers)

    async def run_tasks(self, tasks: list[T], runner: Callable[[T], Awaitable[R]]) -> list[R]:
        semaphore = asyncio.Semaphore(self.max_workers)

        async def _run(task: T) -> R:
            async with semaphore:
                return await runner(task)

        return await asyncio.gather(*(_run(t) for t in tasks))
