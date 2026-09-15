import httpx
import pytest

from noctis.agents.idor import IDORAgent
from test_agents_common import build_context


@pytest.mark.asyncio
async def test_adjacent_numeric_id_returns_distinct_data(tmp_path, httpx_mock):
    node_data = {"type": "endpoint", "method": "GET", "url": "https://example.com/users/100"}

    def responder(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/100"):
            return httpx.Response(200, text="user profile: Alice, email: alice@example.com")
        if path.endswith("/101"):
            return httpx.Response(200, text="user profile: Bob, email: bob@example.com")
        return httpx.Response(404, text="not found")

    httpx_mock.add_callback(responder, is_reusable=True)
    agent = IDORAgent(build_context(tmp_path, node_data))
    result = await agent.execute()

    assert result.found is True
    assert "not gated by an ownership check" in result.evidence


@pytest.mark.asyncio
async def test_no_idor_when_adjacent_id_denied(tmp_path, httpx_mock):
    node_data = {"type": "endpoint", "method": "GET", "url": "https://example.com/users/100"}

    def responder(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/100"):
            return httpx.Response(200, text="user profile: Alice")
        return httpx.Response(403, text="forbidden")

    httpx_mock.add_callback(responder, is_reusable=True)
    agent = IDORAgent(build_context(tmp_path, node_data))
    result = await agent.execute()

    assert result.found is False


@pytest.mark.asyncio
async def test_form_nodes_are_skipped(tmp_path):
    node_data = {"type": "form", "page_url": "https://example.com/", "action": "https://example.com/submit", "method": "POST", "inputs": ["comment"]}
    agent = IDORAgent(build_context(tmp_path, node_data))
    result = await agent.execute()
    assert result.found is False
    assert "form submission" in result.notes
