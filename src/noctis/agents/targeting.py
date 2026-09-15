"""Turns a graph node's attributes (as stored by the attack surface graph) into
something an HTTP agent can actually send payloads against.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


@dataclass
class InjectionTarget:
    method: str
    url: str
    param_names: list[str]
    is_form: bool  # True -> params belong in the POST body, False -> query string


def build_target(node_data: dict) -> InjectionTarget | None:
    node_type = node_data.get("type")

    if node_type == "endpoint":
        method = node_data.get("method", "GET")
        url = node_data.get("url")
        if not url:
            return None
        query = parse_qs(urlparse(url).query)
        return InjectionTarget(method=method, url=url, param_names=list(query.keys()), is_form=False)

    if node_type == "form":
        method = node_data.get("method", "GET")
        url = node_data.get("action")
        if not url:
            return None
        is_form = method.upper() != "GET"
        return InjectionTarget(method=method, url=url, param_names=list(node_data.get("inputs", [])), is_form=is_form)

    return None


def apply_payload(target: InjectionTarget, param_name: str, payload: str) -> tuple[str, dict[str, str] | None]:
    """Returns (url, body) with `param_name` set to `payload`; other params keep
    their original values for a query-string target, or a benign placeholder
    for a form target (whose original values we never observed).
    """
    if target.is_form:
        body = {name: (payload if name == param_name else "test") for name in target.param_names}
        return target.url, body

    parsed = urlparse(target.url)
    query = {k: v[0] if v else "" for k, v in parse_qs(parsed.query).items()}
    query[param_name] = payload
    new_url = urlunparse(parsed._replace(query=urlencode(query)))
    return new_url, None


def baseline_request(target: InjectionTarget) -> tuple[str, dict[str, str] | None]:
    """A request with benign values in every param, used to compare against."""
    if target.is_form:
        return target.url, {name: "test" for name in target.param_names}
    parsed = urlparse(target.url)
    query = {k: v[0] if v else "test" for k, v in parse_qs(parsed.query).items()}
    return urlunparse(parsed._replace(query=urlencode(query))), None
