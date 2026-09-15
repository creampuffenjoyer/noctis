import httpx
import pytest

from noctis.agents.ssrf import SSRFAgent
from test_agents_common import build_context


@pytest.mark.asyncio
async def test_metadata_signature_confirms_ssrf(tmp_path, httpx_mock):
    node_data = {"type": "endpoint", "method": "GET", "url": "https://example.com/fetch?url=https://api.example.com/data"}

    def responder(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "169.254.169.254" in url:
            return httpx.Response(200, text='{"instance-id": "i-0abcd1234", "ami-id": "ami-123"}')
        return httpx.Response(200, text="fetched external data")

    httpx_mock.add_callback(responder, is_reusable=True)
    agent = SSRFAgent(build_context(tmp_path, node_data))
    result = await agent.execute()

    assert result.found is True
    assert "SSRF confirmed" in result.evidence


@pytest.mark.asyncio
async def test_no_ssrf_when_nothing_reflects(tmp_path, httpx_mock):
    node_data = {"type": "endpoint", "method": "GET", "url": "https://example.com/fetch?url=https://api.example.com/data"}
    httpx_mock.add_response(text="fetched external data", is_reusable=True)

    agent = SSRFAgent(build_context(tmp_path, node_data))
    result = await agent.execute()

    assert result.found is False
