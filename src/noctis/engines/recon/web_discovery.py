"""Web discovery agent: spiders the target, maps endpoints/forms/APIs, fingerprints the stack.

Every request goes through ScopeEngine.assert_in_scope() before it is sent —
this is the enforcement point the plan calls "scope enforcement is non-negotiable".
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from noctis.config.settings import Settings
from noctis.core.scope import ScopeEngine, ScopeViolationError

logger = logging.getLogger("noctis.recon.web_discovery")

DEFAULT_HEADERS = {"User-Agent": "Noctis/0.1 (authorized security assessment)"}

# Heuristics for JS analyzer: paths embedded in fetch/axios calls or plain string literals.
JS_ROUTE_PATTERN = re.compile(
    r"""(?:fetch|axios\.\w+|url|endpoint)\s*\(\s*['"](/[a-zA-Z0-9_\-/{}.:]+)['"]""",
)
JS_BARE_API_PATTERN = re.compile(r"""['"](/api/[a-zA-Z0-9_\-/{}.]+)['"]""")

CMS_MARKERS = {
    "wp-content": "WordPress",
    "wp-includes": "WordPress",
    "/sites/default/": "Drupal",
    "Joomla!": "Joomla",
    "csrf-token": "generic-framework",
}


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    source: str = "link"

    def to_dict(self) -> dict:
        return {"url": self.url, "method": self.method, "source": self.source}


@dataclass
class Form:
    page_url: str
    action: str
    method: str
    inputs: list[str]

    def to_dict(self) -> dict:
        return {
            "page_url": self.page_url,
            "action": self.action,
            "method": self.method,
            "inputs": self.inputs,
        }


@dataclass
class Fingerprint:
    server: str | None = None
    powered_by: str | None = None
    cms: str | None = None
    cookies: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "server": self.server,
            "powered_by": self.powered_by,
            "cms": self.cms,
            "cookies": self.cookies,
            "notes": self.notes,
        }


@dataclass
class WebDiscoveryResult:
    target: str
    endpoints: list[Endpoint] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    js_routes: list[str] = field(default_factory=list)
    fingerprint: Fingerprint = field(default_factory=Fingerprint)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "forms": [f.to_dict() for f in self.forms],
            "js_routes": sorted(set(self.js_routes)),
            "fingerprint": self.fingerprint.to_dict(),
            "errors": self.errors,
        }


class _RateLimiter:
    def __init__(self, requests_per_second: float):
        self._min_interval = 1.0 / requests_per_second if requests_per_second > 0 else 0.0
        self._last_call = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        if self._min_interval <= 0:
            return
        async with self._lock:
            elapsed = time.monotonic() - self._last_call
            remaining = self._min_interval - elapsed
            if remaining > 0:
                await asyncio.sleep(remaining)
            self._last_call = time.monotonic()


async def discover(target: str, scope: ScopeEngine, settings: Settings) -> WebDiscoveryResult:
    result = WebDiscoveryResult(target=target)
    rate_limiter = _RateLimiter(settings.requests_per_second)
    seen: set[str] = set()
    queue: list[tuple[str, int]] = [(target, 0)]
    js_files: set[str] = set()

    async with httpx.AsyncClient(headers=DEFAULT_HEADERS, follow_redirects=True, timeout=15.0) as client:
        while queue:
            url, depth = queue.pop(0)
            if url in seen or depth > settings.max_scan_depth:
                continue
            seen.add(url)

            try:
                scope.assert_in_scope(url)
            except ScopeViolationError as exc:
                result.errors.append(str(exc))
                continue

            await rate_limiter.wait()
            try:
                response = await client.get(url)
            except httpx.HTTPError as exc:
                result.errors.append(f"GET {url} failed: {exc}")
                continue

            result.endpoints.append(Endpoint(url=url, method="GET", source="crawl"))

            if url == target:
                _fingerprint_from_response(response, result.fingerprint)

            content_type = response.headers.get("content-type", "")
            if "html" not in content_type and depth > 0:
                continue

            soup = BeautifulSoup(response.text, "lxml")
            _fingerprint_from_html(soup, result.fingerprint)

            for link in soup.find_all("a", href=True):
                next_url = urljoin(url, link["href"])
                if urlparse(next_url).scheme in ("http", "https") and next_url not in seen:
                    queue.append((next_url, depth + 1))

            for script in soup.find_all("script", src=True):
                js_files.add(urljoin(url, script["src"]))

            for form_tag in soup.find_all("form"):
                action = urljoin(url, form_tag.get("action") or url)
                method = (form_tag.get("method") or "GET").upper()
                inputs = [
                    inp.get("name")
                    for inp in form_tag.find_all(["input", "textarea", "select"])
                    if inp.get("name")
                ]
                result.forms.append(Form(page_url=url, action=action, method=method, inputs=inputs))
                result.endpoints.append(Endpoint(url=action, method=method, source="form"))

        for js_url in js_files:
            try:
                scope.assert_in_scope(js_url)
            except ScopeViolationError:
                continue
            await rate_limiter.wait()
            try:
                response = await client.get(js_url)
            except httpx.HTTPError as exc:
                result.errors.append(f"GET {js_url} failed: {exc}")
                continue
            result.js_routes.extend(_extract_js_routes(response.text))

    return result


def _fingerprint_from_response(response: httpx.Response, fp: Fingerprint) -> None:
    fp.server = response.headers.get("server")
    fp.powered_by = response.headers.get("x-powered-by")
    fp.cookies = sorted({c.name for c in response.cookies.jar})


def _fingerprint_from_html(soup: BeautifulSoup, fp: Fingerprint) -> None:
    generator = soup.find("meta", attrs={"name": "generator"})
    if generator and generator.get("content"):
        fp.notes.append(f"generator: {generator['content']}")

    html = str(soup)
    for marker, cms in CMS_MARKERS.items():
        if marker in html and fp.cms is None:
            fp.cms = cms


def _extract_js_routes(js_text: str) -> list[str]:
    routes = set(JS_ROUTE_PATTERN.findall(js_text))
    routes.update(JS_BARE_API_PATTERN.findall(js_text))
    return sorted(routes)
