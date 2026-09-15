"""XSS agent: confirms actual JavaScript execution in a real headless browser
rather than just checking whether the payload was reflected in the response
body (which produces a lot of false positives on its own). Covers reflected
XSS on query-string endpoints and XSS via form submission; DOM-based and
stored XSS would need a stateful multi-step crawl and are out of scope for
this pass.
"""
from __future__ import annotations

import uuid

from noctis.agents.base_agent import AgentResult
from noctis.agents.http_agent import HttpAgent
from noctis.agents.targeting import apply_payload

MARKER_PREFIX = "NOCTIS_XSS_"
NAV_TIMEOUT_MS = 10_000


class XSSAgent(HttpAgent):
    agent_type = "xss"

    def __init__(self, context):
        super().__init__(context)
        self._playwright = None
        self._browser = None

    async def setup(self) -> None:
        await super().setup()
        from playwright.async_api import async_playwright

        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(headless=True)

    async def cleanup(self) -> None:
        if self._browser is not None:
            await self._browser.close()
        if self._playwright is not None:
            await self._playwright.stop()
        await super().cleanup()

    async def run(self) -> AgentResult:
        if self.target is None or not self.target.param_names:
            return self.no_target_result()
        if self._browser is None:
            return AgentResult(found=False, notes="browser failed to start")

        for param in self.target.param_names:
            marker = uuid.uuid4().hex[:8]
            payload = f"<script>alert('{MARKER_PREFIX}{marker}')</script>"

            if self.target.is_form:
                triggered = await self._submit_form(param, payload, marker)
                url_for_request = self.context.node_data.get("page_url", self.target.url)
            else:
                url, _ = apply_payload(self.target, param, payload)
                triggered = await self._navigate(url, marker)
                url_for_request = url

            if triggered:
                async def recheck(p=param, pl=payload, m=marker) -> bool:
                    if self.target.is_form:
                        return await self._submit_form(p, pl, m)
                    u, _ = apply_payload(self.target, p, pl)
                    return await self._navigate(u, m)

                self._recheck = recheck
                return AgentResult(
                    found=True,
                    payload=payload,
                    request=self._format_request(self.target.method, url_for_request),
                    response=f"alert() fired with marker {MARKER_PREFIX}{marker}",
                    evidence=f"confirmed JavaScript execution via param '{param}' in a real browser",
                )

        return AgentResult(found=False, notes=f"no XSS execution confirmed across {len(self.target.param_names)} param(s)")

    async def _navigate(self, url: str, marker: str) -> bool:
        self.context.scope.assert_in_scope(url)
        page = await self._browser.new_page()
        triggered = {"value": False}

        async def on_dialog(dialog):
            if MARKER_PREFIX + marker in (dialog.message or ""):
                triggered["value"] = True
            await dialog.dismiss()

        page.on("dialog", on_dialog)
        try:
            await page.goto(url, timeout=NAV_TIMEOUT_MS, wait_until="load")
            await page.wait_for_timeout(500)
        except Exception:
            pass
        finally:
            await page.close()
        return triggered["value"]

    async def _submit_form(self, param: str, payload: str, marker: str) -> bool:
        page_url = self.context.node_data.get("page_url")
        action = self.context.node_data.get("action", "")
        if not page_url or self.target is None:
            return False
        self.context.scope.assert_in_scope(page_url)

        page = await self._browser.new_page()
        triggered = {"value": False}

        async def on_dialog(dialog):
            if MARKER_PREFIX + marker in (dialog.message or ""):
                triggered["value"] = True
            await dialog.dismiss()

        page.on("dialog", on_dialog)
        try:
            await page.goto(page_url, timeout=NAV_TIMEOUT_MS, wait_until="load")
            action_path = action.rsplit("/", 1)[-1] or action
            form = page.locator(f'form[action*="{action_path}"]').first
            for name in self.target.param_names:
                value = payload if name == param else "test"
                try:
                    await form.locator(f'[name="{name}"]').first.fill(value, timeout=2000)
                except Exception:
                    continue
            try:
                await form.locator('button[type=submit], input[type=submit]').first.click(timeout=2000)
            except Exception:
                await form.evaluate("f => f.submit()")
            await page.wait_for_timeout(800)
        except Exception:
            pass
        finally:
            await page.close()
        return triggered["value"]
