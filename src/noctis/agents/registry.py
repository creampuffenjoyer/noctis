"""Maps a test planner agent_type string to the agent class that handles it."""
from __future__ import annotations

from noctis.agents.auth import AuthAgent
from noctis.agents.base_agent import BaseAgent
from noctis.agents.credential_exposure import CredentialExposureAgent
from noctis.agents.idor import IDORAgent
from noctis.agents.lfi import LFIAgent
from noctis.agents.rce import RCEAgent
from noctis.agents.sqli import SQLiAgent
from noctis.agents.ssrf import SSRFAgent
from noctis.agents.xss import XSSAgent
from noctis.agents.xxe import XXEAgent

AGENT_REGISTRY: dict[str, type[BaseAgent]] = {
    "sqli": SQLiAgent,
    "xss": XSSAgent,
    "ssrf": SSRFAgent,
    "auth": AuthAgent,
    "idor": IDORAgent,
    "rce": RCEAgent,
    "lfi": LFIAgent,
    "xxe": XXEAgent,
    "credential_exposure": CredentialExposureAgent,
}
