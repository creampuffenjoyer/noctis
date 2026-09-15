# 𝓝𝓸𝓬𝓽𝓲𝓼

**An autonomous AI pentester that finds real vulnerabilities, proves them with working exploits, and writes the report for you.**

[![Python](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![uv](https://img.shields.io/badge/managed%20with-uv-de5fe9)](https://github.com/astral-sh/uv)
[![Typer](https://img.shields.io/badge/CLI-Typer%20%2B%20Rich-6f42c1)](https://typer.tiangolo.com/)
[![Status](https://img.shields.io/badge/status-phase%206%20of%2010-yellow)](#where%20it%20stands)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Made for](https://img.shields.io/badge/made%20for-authorized%20engagements-critical)](#responsible%20use)

## What it does

Point Noctis at a target URL (and optionally its source code), and it works through a full pentest pipeline on its own: it spiders the app, fingerprints the stack, traces user input to dangerous sinks in the code, builds a graph of the entire attack surface, and (in later phases) prioritizes and launches real exploitation agents against it. Every finding has to survive a replay before it gets reported, so what comes out the other end is a client ready report backed by proof, not a list of guesses from a scanner.

It runs locally on your own machine, talks to whichever AI provider you configure (Gemini, OpenAI, Claude, or OpenRouter), and is meant to hold up under real professional engagements as well as CTF competitions.

## How it works

```mermaid
flowchart TD
    A[Scope + Config Engine] --> B[Recon Engine]
    B --> C1[Web Discovery]
    B --> C2[Code Analysis]
    C1 --> D[Attack Surface Graph]
    C2 --> D
    D --> E[Risk Engine]
    E --> F[Test Planner]
    F --> G1[SQLi]
    F --> G2[XSS]
    F --> G3[SSRF]
    F --> G4[Auth]
    F --> G5[IDOR]
    F --> G6[RCE / LFI / XXE]
    G1 --> H[Validator]
    G2 --> H
    G3 --> H
    G4 --> H
    G5 --> H
    G6 --> H
    H --> I[Evidence Store]
    I --> J[Report Engine]
    J --> K1[PDF]
    J --> K2[SARIF]
    J --> K3[Markdown]
    J --> K4[JSON]
```

Everything an agent thinks or decides runs through a single model router, so swapping providers never means touching agent code.

The pipeline maps onto standard pentest methodology: recon (`RECON`), threat
modeling (`GRAPH` + `RISK`'s attack chain detection), vulnerability analysis
(`RISK` scoring + `PLANNER`), and exploitation (`EXPLOIT`). Reporting lands
in Phase 6. Post-exploitation/chaining confirmed findings together into a
deeper attack narrative isn't in the plan yet -- that's a real gap, not an
oversight, and will need its own phase between `EXPLOIT` and `VALIDATE`.

## Getting started

```bash
uv sync
uv run playwright install chromium
```

Then create a `.env` file in the project root with at least one model API key set:

```env
GEMINI_API_KEY=your_gemini_key_here
OPENAI_API_KEY=your_openai_key_here
ANTHROPIC_API_KEY=your_anthropic_key_here
OPENROUTER_API_KEY=your_openrouter_key_here

DEFAULT_MODEL=gemini
MAX_WORKERS=3
REQUESTS_PER_SECOND=10
MAX_SCAN_DEPTH=5
CONFIRM_DESTRUCTIVE=true
REPORT_OUTPUT_DIR=./reports
WORKSPACE_DIR=./workspaces
```

## Usage

```bash
# Start a scan (spiders the target, optionally analyzes local source)
uv run noctis scan --url https://example.com --repo /path/to/code

# Preview what a scan would do without sending a single request
uv run noctis scan --url https://example.com --dry-run

# List past scan sessions
uv run noctis workspaces list

# Resume an interrupted scan
uv run noctis resume --workspace <id>

# Generate a report once VALIDATE has run -- json | markdown | sarif | pdf
uv run noctis report --workspace <id> --format json
uv run noctis report --workspace <id> --format markdown
uv run noctis report --workspace <id> --format sarif
uv run noctis report --workspace <id> --format pdf
```

Noctis is built as a triage tool you work with, not something you point and
walk away from. A plain `scan` stops right after the prioritized exploitation
queue is printed so you can review it; nothing gets attacked until you say so:

```bash
# Review the queue only -- no exploitation happens yet
uv run noctis scan --url https://example.com --repo /path/to/code

# Launch exploitation agents against that queue once you've reviewed it
uv run noctis resume --workspace <id> --exploit

# Or do both in one shot (still prompts for confirmation unless --yes)
uv run noctis scan --url https://example.com --repo /path/to/code --exploit
```

That queue-then-confirm behavior is about the EXPLOIT stage specifically and
always applies. Separately, `--mode` controls how the earlier, read-only
stages (recon/graph/risk/planner) are paced:

```bash
# continuous (default): recon -> graph -> risk -> planner run back to back
uv run noctis scan --url https://example.com --mode continuous

# guided: pause after every single stage, review, then `resume` to continue
uv run noctis scan --url https://example.com --mode guided
uv run noctis resume --workspace <id> --mode guided   # advances exactly one stage
```

Either mode can be stopped early with Ctrl-C -- the first press finishes the
stage currently running rather than killing it mid-request, then pauses at
that boundary; a second Ctrl-C force-quits if something's stuck.

## Where it stands

| Piece | State |
|---|---|
| CLI + Rich TUI | Done |
| Model router (Gemini / OpenAI / Claude / OpenRouter) | Done |
| Scope engine, enforced on every request | Done |
| SQLite workspace manager with resume | Done |
| Web discovery (spider, fingerprinting, JS route extraction) | Done |
| Static code analysis (routes, sinks, secrets) | Done |
| NetworkX attack surface graph | Done |
| Risk engine (exploitability x impact scoring, attack chain detection) | Done |
| Test planner (prioritized exploitation queue) + concurrency manager | Done |
| Exploit agent base class | Done |
| Exploitation agents (SQLi, XSS, SSRF, Auth, IDOR, RCE, LFI, XXE, credential exposure) | Done |
| Validator (independent replay, false-positive filtering) | Done |
| CVSS v3.1 scoring + severity, OWASP Top 10 / MITRE ATT&CK classification | Done |
| Evidence store (request/response, PoC scripts, XSS screenshots) | Done |
| Report engine (PDF / SARIF 2.1.0 / Markdown / JSON) | Done |
| FastAPI backend + React dashboard | Planned |

`noctis scan` runs every stage that exists today and stops cleanly once it reaches one that doesn't, rather than pretending to finish. The exploitation stage additionally never fires without an explicit `--exploit` flag (and a confirmation prompt, unless `CONFIRM_DESTRUCTIVE=false` or `--yes`) -- Noctis is meant to be a triage tool you operate, not something that attacks a target on its own.

Every confirmed finding is re-run independently by the Validator (a fresh agent instance, not just re-checking a cached request) before it's kept -- if it doesn't reproduce, it's discarded but still shown to you, not silently dropped. Kept findings get a CVSS v3.1 base score (the real formula, against a documented heuristic vector per vulnerability class -- there's no human assessor in the loop, so treat it as a starting point), an OWASP Top 10 2021 category, and a MITRE ATT&CK tactic/technique. The ATT&CK mapping is mostly Initial Access (T1190 - Exploit Public-Facing Application) since Noctis tests a web app from the outside and doesn't model post-exploitation yet; `auth`/`credential_exposure` findings get more specific Credential Access techniques. No CVE IDs are attached -- Noctis's findings are dynamically confirmed against custom application logic, not matched against a known-vulnerability feed, so a CVE tag would be fabricated rather than real.

The report engine uses ReportLab for PDF generation, not WeasyPrint as the original plan suggested -- WeasyPrint needs a native GTK3 runtime that a plain Windows install doesn't have (confirmed by trying it), which would break the project's own cross-platform requirement. ReportLab is a pure-Python wheel with no native dependency, so it Just Works on Windows and Kali alike. The PDF keeps the dark, red/cyan cyberpunk theme the plan asked for: cover page, executive summary, scope & methodology, a findings table sorted by severity, one detail section per finding (CVSS/OWASP/ATT&CK/evidence/remediation, with the XSS screenshot embedded when there is one), and an appendix with every raw request/response. SARIF output is 2.1.0 and uses the spec's `webRequest` field for HTTP-based findings rather than forcing them into a fake source-file location.

Every agent only reports `found=true` after its own immediate re-check reproduces the result, and defaults to safe, non-destructive confirmation techniques (blind/time-based detection, benign canaries, reading a known-harmless file) rather than full exploitation. Heavier techniques -- an actual sqlmap data-extraction pass, default-credential guessing -- stay behind `CONFIRM_DESTRUCTIVE=false` in `.env`.

## Responsible use

Noctis is built to run real exploits. Only ever point it at targets you own or are explicitly authorized to test, and respect the scope you configure. This project isn't intended for, and shouldn't be used for, unauthorized access to systems you don't control.
