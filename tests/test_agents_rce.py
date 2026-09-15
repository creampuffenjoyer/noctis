import httpx
import pytest

from noctis.agents.rce import RCEAgent
from test_agents_common import build_context


@pytest.mark.asyncio
async def test_echo_canary_confirms_rce(tmp_path, httpx_mock):
    node_data = {"type": "endpoint", "method": "GET", "url": "https://example.com/ping?host=127.0.0.1"}

    def responder(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "NOCTIS_RCE_" in url:
            marker = url.split("NOCTIS_RCE_")[1].split("&")[0].split("%")[0]
            return httpx.Response(200, text=f"ping output\nNOCTIS_RCE_{marker}\n")
        return httpx.Response(200, text="ping: unknown host")

    httpx_mock.add_callback(responder, is_reusable=True)
    agent = RCEAgent(build_context(tmp_path, node_data))
    result = await agent.execute()

    assert result.found is True
    assert "command injection confirmed" in result.evidence


@pytest.mark.asyncio
async def test_ssti_confirms_template_injection(tmp_path, httpx_mock):
    node_data = {"type": "endpoint", "method": "GET", "url": "https://example.com/render?name=test"}

    def responder(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "7*7" in url or "7%2A7" in url:
            return httpx.Response(200, text="result: 49")
        return httpx.Response(200, text="hello test")

    httpx_mock.add_callback(responder, is_reusable=True)
    agent = RCEAgent(build_context(tmp_path, node_data))
    result = await agent.execute()

    assert result.found is True
    assert "SSTI" in result.evidence or "template injection" in result.evidence.lower()


@pytest.mark.asyncio
async def test_no_rce_when_nothing_reflects(tmp_path, httpx_mock):
    node_data = {"type": "endpoint", "method": "GET", "url": "https://example.com/ping?host=127.0.0.1"}
    httpx_mock.add_response(text="ping: unknown host", is_reusable=True)

    agent = RCEAgent(build_context(tmp_path, node_data))
    result = await agent.execute()

    assert result.found is False
