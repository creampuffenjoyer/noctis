"""Shared async rate limiter, used by web discovery and every exploitation agent
so no single component can exceed settings.requests_per_second against a target.
"""
from __future__ import annotations

import asyncio
import time


class RateLimiter:
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
