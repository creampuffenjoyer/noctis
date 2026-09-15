"""Noctis CLI entry point (Typer + Rich)."""
from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Annotated

import typer

# Windows terminals often default to a legacy codepage (cp1252) that can't
# encode arbitrary Unicode from scanned page content or SDK output. Degrade
# gracefully instead of crashing the whole scan on a stray character.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(errors="replace")
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from noctis.config.settings import ModelProvider, get_settings
from noctis.core.model_router import ModelRouter
from noctis.core.orchestrator import ALL_STAGES, IMPLEMENTED_STAGES, Orchestrator, PipelineStage
from noctis.core.scope import ScopeEngine
from noctis.core.workspace import WorkspaceManager, WorkspaceNotFoundError

__version__ = "0.1.0"

app = typer.Typer(name="noctis", no_args_is_help=True, add_completion=False)
workspaces_app = typer.Typer(name="workspaces", no_args_is_help=True)
app.add_typer(workspaces_app, name="workspaces")

console = Console()

STAGE_ICONS = {
    "started": "[cyan]>[/cyan]",
    "completed": "[green]OK[/green]",
    "failed": "[red]FAIL[/red]",
    "skipped (already completed, resumed from cache)": "[yellow]SKIP[/yellow]",
    "not yet implemented - stopping pipeline here": "[yellow]...[/yellow]",
}


def _setup_logging(workspace_dir: Path | None = None) -> None:
    handlers = [RichHandler(console=console, show_path=False, rich_tracebacks=True)]
    logging.basicConfig(level=logging.INFO, format="%(message)s", handlers=handlers)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"noctis {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool, typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version and exit.")
    ] = False,
) -> None:
    """Noctis - autonomous AI pentesting tool."""


def _shorten(text: str, limit: int = 60) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _parse_scope_flag(scope: str | None) -> str | None:
    if scope is None:
        return None
    scope = scope.strip()
    if scope.lower().startswith("only "):
        scope = scope[5:].strip()
    return scope


@app.command()
def scan(
    url: Annotated[str, typer.Option("--url", help="Target base URL, e.g. https://example.com")],
    repo: Annotated[str | None, typer.Option("--repo", help="Local path to source code for static analysis")] = None,
    model: Annotated[
        ModelProvider | None, typer.Option("--model", help="AI provider to use (gemini|openai|claude|openrouter)")
    ] = None,
    auth_user: Annotated[str | None, typer.Option("--auth-user", help="Username for authenticated scanning")] = None,
    auth_pass: Annotated[str | None, typer.Option("--auth-pass", help="Password for authenticated scanning")] = None,
    scope: Annotated[str | None, typer.Option("--scope", help='Include pattern, e.g. "only /api/*"')] = None,
    include: Annotated[list[str] | None, typer.Option("--include", help="Glob pattern to include (repeatable)")] = None,
    exclude: Annotated[list[str] | None, typer.Option("--exclude", help="Glob pattern to exclude (repeatable)")] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show what would run without doing it")] = False,
    exploit: Annotated[
        bool, typer.Option("--exploit", help="Launch exploitation agents against the prioritized queue")
    ] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip the exploitation confirmation prompt")] = False,
) -> None:
    """Start a new scan against URL."""
    _setup_logging()
    settings = get_settings()
    model = model or settings.default_model

    if exploit and not dry_run and settings.confirm_destructive and not yes:
        typer.confirm(
            f"This will launch real exploitation agents (SQLi, XSS, SSRF, Auth, IDOR, RCE, LFI, XXE) "
            f"against {url}. You confirm you are authorized to test this target. Continue?",
            abort=True,
        )

    include_patterns = list(include or [])
    scope_pattern = _parse_scope_flag(scope)
    if scope_pattern:
        include_patterns.append(scope_pattern)
    exclude_patterns = list(exclude or [])

    if auth_user or auth_pass:
        console.print(
            "[yellow]Note:[/yellow] --auth-user/--auth-pass are accepted but authenticated crawling "
            "is not implemented yet (planned for a later phase)."
        )

    if dry_run:
        console.print("[bold]Dry run - no requests will be sent.[/bold]")
        table = Table(show_header=False, box=None)
        table.add_row("Target", url)
        table.add_row("Repo", repo or "(none)")
        table.add_row("Model", model.value)
        table.add_row("Include patterns", ", ".join(include_patterns) or "(all in-scope)")
        table.add_row("Exclude patterns", ", ".join(exclude_patterns) or "(none)")
        table.add_row(
            "Stages that would run",
            ", ".join(s.value for s in ALL_STAGES if s in IMPLEMENTED_STAGES),
        )
        table.add_row("Exploitation agents", "would run (--exploit passed)" if exploit else "queue only, not launched")
        table.add_row(
            "Stages not yet implemented",
            ", ".join(s.value for s in ALL_STAGES if s not in IMPLEMENTED_STAGES),
        )
        console.print(table)
        raise typer.Exit()

    workspace_manager = WorkspaceManager(settings)
    scope_engine = ScopeEngine(target=url, include=include_patterns, exclude=exclude_patterns)
    workspace = workspace_manager.create(
        target=url,
        repo_path=repo,
        model_provider=model.value,
        scope={"include": include_patterns, "exclude": exclude_patterns},
    )
    console.print(f"[bold green]Workspace created:[/bold green] {workspace.id}")

    _run_pipeline(
        workspace_manager, workspace.id, scope_engine, settings, repo_path=repo, resume=False, run_exploit=exploit
    )


@app.command()
def resume(
    workspace: Annotated[str, typer.Option("--workspace", help="Workspace ID to resume")],
    exploit: Annotated[
        bool, typer.Option("--exploit", help="Launch exploitation agents against the prioritized queue")
    ] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip the exploitation confirmation prompt")] = False,
) -> None:
    """Resume an interrupted scan."""
    _setup_logging()
    settings = get_settings()
    workspace_manager = WorkspaceManager(settings)

    try:
        ws = workspace_manager.get(workspace)
    except WorkspaceNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    if exploit and settings.confirm_destructive and not yes:
        typer.confirm(
            f"This will launch real exploitation agents (SQLi, XSS, SSRF, Auth, IDOR, RCE, LFI, XXE) "
            f"against {ws.target}. You confirm you are authorized to test this target. Continue?",
            abort=True,
        )

    scope_engine = ScopeEngine(
        target=ws.target,
        include=ws.scope.get("include", []),
        exclude=ws.scope.get("exclude", []),
    )
    console.print(f"[bold]Resuming workspace {ws.id}[/bold] (target: {ws.target})")
    _run_pipeline(
        workspace_manager, ws.id, scope_engine, settings, repo_path=ws.repo_path, resume=True, run_exploit=exploit
    )


def _run_pipeline(
    workspace_manager: WorkspaceManager,
    workspace_id: str,
    scope_engine: ScopeEngine,
    settings,
    *,
    repo_path: str | None,
    resume: bool,
    run_exploit: bool = False,
) -> None:
    ws = workspace_manager.get(workspace_id)

    def on_stage(stage: PipelineStage, status: str) -> None:
        icon = STAGE_ICONS.get(status, "[white]*[/white]")
        console.print(f"{icon} [bold]{stage.value}[/bold]: {status}")

    orchestrator = Orchestrator(
        workspace=ws,
        workspace_manager=workspace_manager,
        scope=scope_engine,
        settings=settings,
        model_router=ModelRouter(settings),
        on_stage=on_stage,
    )

    with console.status("[bold cyan]Running Noctis pipeline...", spinner="dots"):
        try:
            results = asyncio.run(orchestrator.run(repo_path=repo_path, resume=resume, run_exploit=run_exploit))
        except Exception as exc:
            if workspace_manager.get(workspace_id).status == "running":
                workspace_manager.update_status(workspace_id, "failed")
            console.print(f"[bold red]Pipeline failed:[/bold red] {exc}")
            raise typer.Exit(code=1) from exc

    console.print(f"\n[bold]Workspace:[/bold] {ws.id}")
    if "graph" in results:
        summary = results["graph"].get("summary", {})
        table = Table(title="Attack Surface Summary")
        table.add_column("Node type")
        table.add_column("Count", justify="right")
        for node_type, count in summary.items():
            table.add_row(node_type, str(count))
        console.print(table)

    if "planner" in results:
        queue = results["planner"].get("queue", [])
        table = Table(title=f"Exploitation Queue (top {min(10, len(queue))} of {len(queue)})")
        table.add_column("Priority", justify="right")
        table.add_column("Agent")
        table.add_column("Node")
        table.add_column("Rationale")
        for task in queue[:10]:
            table.add_row(
                f"{task['priority_score']:.1f}",
                task["agent_type"],
                _shorten(task["node_id"]),
                task["rationale"],
            )
        console.print(table)

    if "exploit" in results:
        exploit_results = results["exploit"]
        findings = exploit_results.get("findings", [])
        console.print(
            f"\n[bold]Exploitation results:[/bold] {exploit_results.get('found', 0)} confirmed "
            f"of {exploit_results.get('total', 0)} attempted"
        )
        if findings:
            table = Table(title="Confirmed Findings")
            table.add_column("Agent")
            table.add_column("Node")
            table.add_column("Payload")
            table.add_column("Evidence")
            for f in findings:
                result = f.get("result", {})
                table.add_row(
                    f["agent_type"],
                    _shorten(f["node_id"]),
                    _shorten(result.get("payload", ""), 40),
                    _shorten(result.get("evidence", "")),
                )
            console.print(table)
        errors = [t for t in exploit_results.get("tasks", []) if t.get("error")]
        if errors:
            console.print(f"[yellow]{len(errors)} agent(s) errored out (see workspace log for details)[/yellow]")

    if "planner" in results and "exploit" not in results:
        console.print(
            f"Run [bold]noctis resume --workspace {ws.id} --exploit[/bold] to launch exploitation agents "
            f"against the queue above, once you've reviewed it."
        )
    console.print(f"Run [bold]noctis report --workspace {ws.id} --format json[/bold] to view raw findings.")


@app.command()
def report(
    workspace: Annotated[str, typer.Option("--workspace", help="Workspace ID")],
    format: Annotated[str, typer.Option("--format", help="Output format: json (others not implemented yet)")] = "json",
) -> None:
    """Generate a report from a completed (or in-progress) scan."""
    settings = get_settings()
    workspace_manager = WorkspaceManager(settings)

    try:
        ws = workspace_manager.get(workspace)
    except WorkspaceNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    if format != "json":
        console.print(
            f"[yellow]Format '{format}' is not implemented yet[/yellow] "
            "(PDF/Markdown/SARIF generation is planned for Phase 6). Try --format json."
        )
        raise typer.Exit(code=1)

    data = {"workspace": ws.__dict__}
    for stage in ALL_STAGES:
        stage_data = workspace_manager.load_stage_data(ws.id, stage.value)
        if stage_data is not None:
            data[stage.value] = stage_data

    report_path = workspace_manager.path(ws.id) / "reports" / "report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    console.print(f"[green]Report written to[/green] {report_path}")


@workspaces_app.command("list")
def workspaces_list() -> None:
    """List all past scan sessions."""
    settings = get_settings()
    workspace_manager = WorkspaceManager(settings)
    all_workspaces = workspace_manager.list()

    if not all_workspaces:
        console.print("No workspaces yet. Run [bold]noctis scan --url <target>[/bold] to create one.")
        return

    table = Table(title="Noctis Workspaces")
    table.add_column("ID")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Stage")
    table.add_column("Created")
    for ws in all_workspaces:
        created = ws.created_at.split("+", 1)[0].split(".", 1)[0].replace("T", " ")
        table.add_row(ws.id, ws.target, ws.status, ws.stage or "-", created)
    console.print(table)


if __name__ == "__main__":
    app()
