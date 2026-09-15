"""Evidence store: saves screenshots, request/response pairs, and PoC scripts
for a finding, organized as workspaces/{workspace_id}/evidence/{finding_id}/.

finding_id is deterministic (same agent_type + node_id always produce the
same id), so agents that capture evidence at exploitation time (Phase 4, e.g.
XSS screenshots) and the Validator that organizes the rest of it later (Phase
5) always agree on where a given finding's evidence lives without having to
pass an id between them.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from noctis.core.workspace import WorkspaceManager


def compute_finding_id(agent_type: str, node_id: str) -> str:
    digest = hashlib.sha1(node_id.encode("utf-8")).hexdigest()[:10]
    return f"{agent_type}_{digest}"


class EvidenceStore:
    def __init__(self, workspace_manager: WorkspaceManager, workspace_id: str):
        self.workspace_manager = workspace_manager
        self.workspace_id = workspace_id

    def finding_dir(self, finding_id: str) -> Path:
        path = self.workspace_manager.path(self.workspace_id) / "evidence" / finding_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def save_screenshot(self, finding_id: str, png_bytes: bytes, name: str = "screenshot.png") -> str:
        path = self.finding_dir(finding_id) / name
        path.write_bytes(png_bytes)
        return str(path)

    def save_request_response(self, finding_id: str, request_text: str, response_text: str) -> str:
        path = self.finding_dir(finding_id) / "request_response.txt"
        path.write_text(
            f"--- REQUEST ---\n{request_text}\n\n--- RESPONSE ---\n{response_text}\n", encoding="utf-8"
        )
        return str(path)

    def save_poc_script(self, finding_id: str, script_text: str) -> str:
        path = self.finding_dir(finding_id) / "poc.py"
        path.write_text(script_text, encoding="utf-8")
        return str(path)
