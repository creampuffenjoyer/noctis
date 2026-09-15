# Noctis

**An autonomous AI pentester that finds real vulnerabilities, proves them with working exploits, and writes the report for you.**

[![Python](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![uv](https://img.shields.io/badge/managed%20with-uv-de5fe9)](https://github.com/astral-sh/uv)
[![Typer](https://img.shields.io/badge/CLI-Typer%20%2B%20Rich-6f42c1)](https://typer.tiangolo.com/)
[![Status](https://img.shields.io/badge/status-phase%202%20of%2010-yellow)](noctis_plan.md)
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

## Getting started

```bash
uv sync
uv run playwright install chromium
cp .env.example .env   # add at least one model API key
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

# Dump raw findings for a workspace
uv run noctis report --workspace <id> --format json
```

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
| Risk scoring + test planner | Planned |
| Exploitation agents (SQLi, XSS, SSRF, Auth, IDOR, RCE, LFI, XXE) | Planned |
| Validator + evidence store | Planned |
| Report engine (PDF / SARIF / Markdown / JSON) | Planned |
| FastAPI backend + React dashboard | Planned |

`noctis scan` runs every stage that exists today and stops cleanly once it reaches one that doesn't, rather than pretending to finish. See [`noctis_plan.md`](noctis_plan.md) for the full ten phase build plan.

## Responsible use

Noctis is built to run real exploits. Only ever point it at targets you own or are explicitly authorized to test, and respect the scope you configure. This project isn't intended for, and shouldn't be used for, unauthorized access to systems you don't control.
