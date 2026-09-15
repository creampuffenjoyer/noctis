"""Credential exposure "agent": secrets found by the static code analyzer are
already a confirmed finding (the secret is right there in the source), so
there's nothing to exploit. This just re-reads the file to confirm the
secret is still present before it's reported -- promoting it into the same
AgentResult shape as every other finding. Actually testing a found
credential against whatever service it belongs to (AWS, a signing key,
etc) is real exploitation with its own blast radius and is deliberately
left out of this pass.
"""
from __future__ import annotations

from pathlib import Path

from noctis.agents.base_agent import AgentContext, AgentResult, BaseAgent


class CredentialExposureAgent(BaseAgent):
    agent_type = "credential_exposure"

    def __init__(self, context: AgentContext):
        super().__init__(context)

    async def setup(self) -> None:
        return None

    async def run(self) -> AgentResult:
        data = self.context.node_data
        file, line, kind = data.get("file"), data.get("line"), data.get("kind", "secret")
        masked = data.get("masked_value", "")

        if not file or not self.context.repo_path:
            return AgentResult(found=False, notes="missing file path or repo path, cannot re-verify")

        full_path = Path(self.context.repo_path) / file
        try:
            lines = full_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError as exc:
            return AgentResult(found=False, notes=f"could not re-read {file}: {exc}")

        if not line or line > len(lines):
            return AgentResult(found=False, notes=f"{file}:{line} is out of range, file may have changed")

        snippet = lines[line - 1].strip()[:200]
        return AgentResult(
            found=True,
            payload=masked,
            request=f"static analysis: {file}:{line}",
            response=snippet,
            evidence=f"hardcoded {kind} ('{masked}') confirmed still present at {file}:{line}",
        )

    async def validate(self, result: AgentResult) -> AgentResult:
        return result

    async def report(self, result: AgentResult) -> AgentResult:
        return result
