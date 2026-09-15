import base64
import json

import httpx
import pytest

from noctis.agents.auth import AuthAgent, _b64url, _b64url_decode
from test_agents_common import build_context


def _sample_jwt() -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"user": "guest", "role": "guest"}).encode())
    return f"{header}.{payload}.deadbeef"


@pytest.mark.asyncio
async def test_jwt_alg_none_accepted(tmp_path, httpx_mock):
    node_data = {"type": "endpoint", "method": "GET", "url": "https://example.com/account"}
    sample_token = _sample_jwt()

    def responder(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
            header = json.loads(_b64url_decode(token.split(".")[0]))
            if header.get("alg") == "none":
                return httpx.Response(200, text="welcome back")
            return httpx.Response(401, text="invalid token")
        return httpx.Response(401, text="unauthenticated", headers=[("set-cookie", f"session={sample_token}")])

    httpx_mock.add_callback(responder, is_reusable=True)
    agent = AuthAgent(build_context(tmp_path, node_data))
    result = await agent.execute()

    assert result.found is True
    assert "alg=none" in result.evidence


@pytest.mark.asyncio
async def test_no_jwt_found_returns_not_found(tmp_path, httpx_mock):
    node_data = {"type": "endpoint", "method": "GET", "url": "https://example.com/account"}
    httpx_mock.add_response(text="plain page, no tokens here", is_reusable=True)

    agent = AuthAgent(build_context(tmp_path, node_data))
    result = await agent.execute()

    assert result.found is False


@pytest.mark.asyncio
async def test_default_credentials_gated_behind_confirm_destructive(tmp_path, httpx_mock):
    node_data = {
        "type": "form",
        "page_url": "https://example.com/login",
        "action": "https://example.com/login",
        "method": "POST",
        "inputs": ["username", "password"],
    }
    httpx_mock.add_response(status_code=401, text="invalid credentials", is_reusable=True)

    context = build_context(tmp_path, node_data, confirm_destructive=True)
    agent = AuthAgent(context)
    result = await agent.execute()

    # confirm_destructive=True (the safe default) means default-credential guessing never fires
    assert result.found is False
