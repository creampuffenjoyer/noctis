# Noctis

Autonomous AI pentesting tool for web applications and APIs. Analyzes source code,
maps attack surfaces, executes real exploits, validates findings, and generates
client-ready reports. Built for authorized professional engagements and CTF use.

See `noctis_plan.md` for the full build plan. This repo currently implements
**Phase 1 (Foundation)** and **Phase 2 (Recon Engine)**.

## Setup

```bash
uv sync
uv run playwright install chromium
cp .env.example .env   # fill in at least one model API key
```

## Usage

```bash
# Start a scan (spiders the target, optionally analyzes local source)
uv run noctis scan --url https://example.com --repo /path/to/code

# Preview what a scan would do without sending any requests
uv run noctis scan --url https://example.com --dry-run

# List past scan sessions
uv run noctis workspaces list

# Resume an interrupted scan
uv run noctis resume --workspace <id>

# Dump raw findings for a workspace
uv run noctis report --workspace <id> --format json
```

## Status

Implemented: CLI skeleton, model router (Gemini/OpenAI/Claude/OpenRouter), scope
engine, SQLite workspace manager, web discovery (spider + fingerprint + JS route
extraction), static code analysis (routes/sinks/secrets), attack surface graph.

Not yet implemented: risk scoring, test planner, exploitation agents, validator,
evidence store, report generation (PDF/SARIF/Markdown), FastAPI backend, web UI.
`noctis scan` runs the implemented stages and stops cleanly after the graph stage.

Only scan targets you are authorized to test.
