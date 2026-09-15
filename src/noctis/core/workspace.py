"""Workspace manager: creates, saves, resumes, and lists scan sessions in SQLite.

Each workspace owns a folder under settings.workspace_dir/{id}/ that holds its
log file, pipeline stage snapshots (for resume), evidence, and reports.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from noctis.config.settings import Settings, get_settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    repo_path TEXT,
    model_provider TEXT,
    status TEXT NOT NULL DEFAULT 'created',
    stage TEXT,
    scope_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Workspace:
    id: str
    target: str
    repo_path: str | None
    model_provider: str | None
    status: str
    stage: str | None
    scope: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""

    @classmethod
    def _from_row(cls, row: sqlite3.Row) -> "Workspace":
        return cls(
            id=row["id"],
            target=row["target"],
            repo_path=row["repo_path"],
            model_provider=row["model_provider"],
            status=row["status"],
            stage=row["stage"],
            scope=json.loads(row["scope_json"]) if row["scope_json"] else {},
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


class WorkspaceManager:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self.settings.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.settings.workspace_dir / "noctis.db"
        with self._connect() as conn:
            conn.execute(SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def path(self, workspace_id: str) -> Path:
        return self.settings.workspace_dir / workspace_id

    def create(
        self,
        target: str,
        repo_path: str | None = None,
        model_provider: str | None = None,
        scope: dict[str, Any] | None = None,
    ) -> Workspace:
        workspace_id = uuid.uuid4().hex[:12]
        now = _now()
        self.path(workspace_id).mkdir(parents=True, exist_ok=True)
        (self.path(workspace_id) / "evidence").mkdir(exist_ok=True)
        (self.path(workspace_id) / "reports").mkdir(exist_ok=True)

        with self._connect() as conn:
            conn.execute(
                """INSERT INTO workspaces
                   (id, target, repo_path, model_provider, status, stage, scope_json, created_at, updated_at)
                   VALUES (?, ?, ?, ?, 'created', NULL, ?, ?, ?)""",
                (workspace_id, target, repo_path, model_provider, json.dumps(scope or {}), now, now),
            )

        ws = Workspace(
            id=workspace_id,
            target=target,
            repo_path=repo_path,
            model_provider=model_provider,
            status="created",
            stage=None,
            scope=scope or {},
            created_at=now,
            updated_at=now,
        )
        self.log(workspace_id, f"workspace created for target={target}")
        return ws

    def get(self, workspace_id: str) -> Workspace:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM workspaces WHERE id = ?", (workspace_id,)).fetchone()
        if row is None:
            raise WorkspaceNotFoundError(f"No workspace with id '{workspace_id}'")
        return Workspace._from_row(row)

    def list(self) -> list[Workspace]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM workspaces ORDER BY created_at DESC").fetchall()
        return [Workspace._from_row(row) for row in rows]

    def update_status(self, workspace_id: str, status: str, stage: str | None = None) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE workspaces SET status = ?, stage = COALESCE(?, stage), updated_at = ? WHERE id = ?",
                (status, stage, _now(), workspace_id),
            )
        self.log(workspace_id, f"status -> {status}" + (f" (stage={stage})" if stage else ""))

    def save_stage_data(self, workspace_id: str, stage: str, data: dict[str, Any]) -> None:
        """Persist a pipeline stage's output so a crashed scan can resume from it."""
        stage_file = self.path(workspace_id) / f"stage_{stage}.json"
        stage_file.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    def load_stage_data(self, workspace_id: str, stage: str) -> dict[str, Any] | None:
        stage_file = self.path(workspace_id) / f"stage_{stage}.json"
        if not stage_file.exists():
            return None
        return json.loads(stage_file.read_text(encoding="utf-8"))

    def log(self, workspace_id: str, message: str) -> None:
        log_file = self.path(workspace_id) / "noctis.log"
        with log_file.open("a", encoding="utf-8") as f:
            f.write(f"[{_now()}] {message}\n")


class WorkspaceNotFoundError(RuntimeError):
    pass
