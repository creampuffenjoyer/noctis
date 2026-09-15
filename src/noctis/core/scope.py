"""Scope engine: defines what Noctis is and is not allowed to touch during a scan.

Every outbound request made anywhere in the pipeline must be checked against
this before it is sent. This is the hard safety boundary for real engagements.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from urllib.parse import urlparse


@dataclass
class ScopeEngine:
    target: str
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    allowed_hosts: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        parsed = urlparse(self.target)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Target must be an absolute URL, got: {self.target!r}")
        self.allowed_hosts.add(parsed.hostname or "")

    def add_allowed_host(self, host: str) -> None:
        self.allowed_hosts.add(host)

    def is_in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.hostname not in self.allowed_hosts:
            return False

        path_and_query = parsed.path + (f"?{parsed.query}" if parsed.query else "")

        for pattern in self.exclude:
            if self._matches(url, path_and_query, pattern):
                return False

        if self.include:
            return any(self._matches(url, path_and_query, pattern) for pattern in self.include)

        return True

    @staticmethod
    def _matches(url: str, path_and_query: str, pattern: str) -> bool:
        pattern = pattern.strip()
        return fnmatch(path_and_query, pattern) or fnmatch(url, pattern)

    def assert_in_scope(self, url: str) -> None:
        if not self.is_in_scope(url):
            raise ScopeViolationError(f"URL is out of scope and was blocked: {url}")


class ScopeViolationError(RuntimeError):
    """Raised when the pipeline attempts to act on an out-of-scope target."""
