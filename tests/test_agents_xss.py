import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from noctis.agents.xss import XSSAgent
from test_agents_common import build_context


class _ReflectingHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        query = parse_qs(urlparse(self.path).query)
        name = query.get("name", [""])[0]
        body = f"<html><body>hello {name}</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002
        pass


@pytest.fixture
def local_server():
    server = HTTPServer(("127.0.0.1", 0), _ReflectingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_port
    server.shutdown()
    thread.join(timeout=5)


@pytest.mark.asyncio
async def test_reflected_xss_confirmed_in_real_browser(tmp_path, local_server):
    base = f"http://127.0.0.1:{local_server}"
    node_data = {"type": "endpoint", "method": "GET", "url": f"{base}/greet?name=world"}
    context = build_context(tmp_path, node_data, target=base)

    agent = XSSAgent(context)
    result = await agent.execute()

    assert result.found is True
    assert "<script>" in result.payload
