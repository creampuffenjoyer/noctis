import httpx
import pytest

from noctis.agents.lfi import LFIAgent
from test_agents_common import build_context


@pytest.mark.asyncio
async def test_path_traversal_confirmed(tmp_path, httpx_mock):
    node_data = {"type": "endpoint", "method": "GET", "url": "https://example.com/view?file=report.txt"}

    def responder(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "etc" in url and "passwd" in url:
            return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin")
        return httpx.Response(200, text="report contents")

    httpx_mock.add_callback(responder, is_reusable=True)
    agent = LFIAgent(build_context(tmp_path, node_data))
    result = await agent.execute()

    assert result.found is True
    assert "root:" in result.evidence


@pytest.mark.asyncio
async def test_no_lfi_when_file_not_reflected(tmp_path, httpx_mock):
    node_data = {"type": "endpoint", "method": "GET", "url": "https://example.com/view?file=report.txt"}
    httpx_mock.add_response(text="file not found", is_reusable=True)

    agent = LFIAgent(build_context(tmp_path, node_data))
    result = await agent.execute()

    assert result.found is False
