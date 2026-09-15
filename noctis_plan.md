# NOCTIS — Master Build Plan
> Autonomous Pentesting Tool


author: Joseph Sollestre
---

## PROJECT OVERVIEW

**What is Noctis?**
Noctis is an autonomous AI pentesting tool for web applications and APIs. It analyzes source code, maps attack surfaces, executes real exploits, validates findings, and generates professional client-ready reports. It runs locally, supports multiple AI model backends, and is built to be used in real professional engagements.

**Core principle:** No exploit, no report. Every finding must have a working proof of concept.

**Target user:** Professional pentester running real client engagements, also usable for CTF competitions.

---

## ARCHITECTURE

```
NOCTIS
       │
┌──────┴──────┐
SCOPE ENGINE   CONFIG ENGINE
       │
       ▼
 RECON ENGINE
       │
┌──────┴──────┐
WEB DISCOVERY  CODE ANALYSIS
       │
       ▼
ATTACK SURFACE GRAPH
       │
       ▼
RISK ENGINE
       │
       ▼
TEST PLANNER
       │
┌──────┼──────┬──────┬──────┐
SQLi  XSS   SSRF   Auth   IDOR  RCE  LFI  XXE
       │
       ▼
VALIDATOR
       │
       ▼
EVIDENCE STORE
       │
       ▼
REPORT ENGINE
       │
┌──────┼──────┐
PDF  SARIF  JSON  Markdown
```

**Interface:** CLI first (Typer + Rich TUI), FastAPI backend + React Web UI in later phases.

**Model Router:** All agents call a unified model router — never the model directly. Supports Gemini API, OpenAI/Codex, Claude API, OpenRouter.

---

## TECH STACK

| Layer | Technology |
|---|---|
| Language | Python 3.11+ |
| CLI | Typer + Rich |
| HTTP client | httpx + requests |
| Browser automation | Playwright |
| Shell execution | subprocess + asyncio |
| AI model calls | Unified model router (Gemini, OpenAI, Claude, OpenRouter) |
| Graph engine | NetworkX |
| Database | SQLite (local workspaces) |
| PDF generation | WeasyPrint or ReportLab |
| SARIF output | Custom serializer |
| Package manager | uv |
| Future backend | FastAPI |
| Future frontend | React + Vite + Tailwind |

---

## FOLDER STRUCTURE

```
noctis/
├── noctis/
│   ├── __init__.py
│   ├── cli/
│   │   └── main.py              # Typer CLI entry point
│   ├── core/
│   │   ├── orchestrator.py      # Pipeline state manager
│   │   ├── model_router.py      # AI model abstraction layer
│   │   ├── workspace.py         # Scan session persistence
│   │   └── scope.py             # Scope + exclusion rules
│   ├── config/
│   │   └── settings.py          # Config engine, env vars, model selection
│   ├── engines/
│   │   ├── recon/
│   │   │   ├── web_discovery.py # Spider, endpoint mapping, fingerprinting
│   │   │   └── code_analysis.py # Source code parsing, sink detection
│   │   ├── graph/
│   │   │   └── attack_surface.py # NetworkX attack surface graph
│   │   ├── risk/
│   │   │   └── risk_engine.py   # Scoring, prioritization, chain detection
│   │   └── planner/
│   │       └── test_planner.py  # Agent assignment, strategy, concurrency
│   ├── agents/
│   │   ├── base_agent.py        # Base class all agents inherit
│   │   ├── sqli.py
│   │   ├── xss.py
│   │   ├── ssrf.py
│   │   ├── auth.py
│   │   ├── idor.py
│   │   ├── rce.py
│   │   ├── lfi.py
│   │   └── xxe.py
│   ├── validator/
│   │   └── validator.py         # PoC confirmation, false positive removal
│   ├── evidence/
│   │   └── store.py             # Screenshots, request/response, PoC scripts
│   └── reporting/
│       ├── pdf_generator.py
│       ├── markdown_generator.py
│       ├── sarif_generator.py
│       └── json_generator.py
├── workspaces/                  # Local scan session storage
├── reports/                     # Generated reports output
├── tests/                       # Unit + integration tests
├── pyproject.toml
├── README.md
├── .env.example
└── PLAN.md                      # This file
```

---

## BUILD PHASES

---

### PHASE 1 — Foundation (Week 1-2)
**Goal:** Working CLI skeleton with model router and workspace management.

**Deliverables:**
- [ ] Project scaffolded with uv, pyproject.toml, folder structure
- [ ] Typer CLI with commands: `scan`, `resume`, `report`, `workspaces`
- [ ] Rich TUI — live progress display, colored output, spinner
- [ ] Model router supporting: Gemini API, OpenAI API, Claude API, OpenRouter
- [ ] Config engine reading from `.env` and CLI flags
- [ ] Scope engine — define target URL, exclusions, rules of engagement
- [ ] Workspace manager — create, save, resume, list scan sessions (SQLite)
- [ ] Orchestrator skeleton — manages pipeline stages, handles errors gracefully
- [ ] Basic logging — all actions logged to workspace folder

**Session 1 prompt for Claude Code:**
> "Scaffold a Python project called Noctis using uv. Create the full folder structure as defined in PLAN.md. Build the Typer CLI with commands: scan, resume, report, workspaces list. Add a Rich TUI that shows live pipeline progress. Build a model router class that abstracts Gemini API, OpenAI API, Claude API, and OpenRouter behind a single interface: router.think(prompt, context). Build a workspace manager using SQLite that creates, saves, resumes, and lists scan sessions. Build a scope engine that accepts target URL, exclusion patterns, and rules of engagement. Read all credentials from .env file. Add a .env.example. Make it run on Windows and Kali Linux."

**Test:** Run `noctis scan --url https://example.com --model gemini` and see the TUI start with workspace created.

---

### PHASE 2 — Recon Engine (Week 3-4)
**Goal:** Noctis can autonomously discover the full attack surface of a target.

**Deliverables:**
- [ ] Web discovery agent — spider target, find all URLs, endpoints, forms, APIs
- [ ] Stack fingerprinting — identify framework, language, server, CMS
- [ ] Auth mapper — detect login forms, JWT usage, session mechanisms, API keys
- [ ] JavaScript analyzer — extract API routes and endpoints from JS files
- [ ] Code analysis agent — parse source code (if provided), map routes to files
- [ ] Data flow tracer — find where user input flows to dangerous sinks
- [ ] Secret scanner — find hardcoded credentials, API keys, tokens in code
- [ ] Attack surface graph builder — NetworkX graph of all discovered nodes

**Session 2 prompt for Claude Code:**
> "Build the Recon Engine for Noctis as defined in PLAN.md Phase 2. Web discovery should spider the target URL, find all endpoints, forms, input parameters, and API routes. Add stack fingerprinting using HTTP headers, error pages, and response patterns. Build a JavaScript analyzer that extracts API routes from JS files. Build a code analysis agent that accepts a local repo path, maps routes to source files, traces user input to dangerous sinks (SQL queries, eval, exec, file operations, subprocess calls, render functions), and scans for hardcoded secrets. Output everything into an Attack Surface Graph using NetworkX where nodes are endpoints/functions and edges are data flows and trust boundaries."

**Test:** Run `noctis scan --url https://testphp.vulnweb.com --repo /path/to/code` and see a full attack surface map printed.

---

### PHASE 3 — Risk Engine + Test Planner (Week 5-6)
**Goal:** Noctis intelligently prioritizes what to attack and in what order.

**Deliverables:**
- [ ] Risk scorer — scores each graph node by exploitability × impact
- [ ] Attack chain detector — finds paths through the graph that chain vulnerabilities
- [ ] Test planner — assigns exploitation agents to nodes based on risk score
- [ ] Concurrency manager — runs multiple agents in parallel safely
- [ ] Agent base class — standard interface all exploit agents inherit

**Session 3 prompt for Claude Code:**
> "Build the Risk Engine and Test Planner for Noctis as defined in PLAN.md Phase 3. The risk engine takes the Attack Surface Graph and scores each node using: input type, authentication requirement, data flow to dangerous sinks, stack vulnerability history, and HTTP method. Build an attack chain detector that traverses the graph to find multi-hop exploitation paths. Build a test planner that reads the scored graph and assigns exploitation agents to nodes in priority order. Add concurrency so multiple agents can run in parallel with a configurable max_workers setting. Build a BaseAgent class with standard methods: setup(), run(), validate(), report() that all exploit agents will inherit."

**Test:** Feed a sample attack surface graph and see a prioritized exploitation queue printed.

---

### PHASE 4 — Exploitation Agents (Week 7-9)
**Goal:** Noctis can execute real exploits across all major vulnerability classes.

**Deliverables:**
- [ ] SQLi agent — manual payloads + sqlmap integration, confirms data extraction
- [ ] XSS agent — reflected, stored, DOM — Playwright confirms execution in browser
- [ ] SSRF agent — probes internal endpoints, OOB callbacks via interactsh
- [ ] Auth agent — bypass attempts, JWT attacks, brute force, session fixation
- [ ] IDOR agent — manipulates object references, confirms unauthorized access
- [ ] RCE agent — command injection, deserialization, template injection
- [ ] LFI agent — path traversal, file inclusion, log poisoning
- [ ] XXE agent — XML injection, external entity, blind XXE

**Session 4 prompt for Claude Code:**
> "Build all exploitation agents for Noctis as defined in PLAN.md Phase 4. Each agent inherits BaseAgent. SQLi agent tries manual payloads first then falls back to sqlmap, must confirm actual data extraction to report. XSS agent tries reflected, stored, and DOM XSS payloads, uses Playwright headless browser to confirm JavaScript execution. SSRF agent probes internal IPs and cloud metadata endpoints (169.254.169.254, 10.x.x.x). Auth agent tests for JWT none algorithm, weak secrets, session fixation, and default credentials. IDOR agent modifies numeric IDs and UUIDs in parameters and path segments, confirms different user data returned. All agents must return: found (bool), payload (str), request (str), response (str), evidence (str)."

**Test:** Run each agent against DVWA or testphp.vulnweb.com and confirm findings.

---

### PHASE 5 — Validator + Evidence Store (Week 10)
**Goal:** Every finding is confirmed, evidenced, and stored properly.

**Deliverables:**
- [ ] Validator — replays exploit, confirms reproducibility, assigns CVSS score
- [ ] False positive filter — removes findings that can't be reproduced
- [ ] Evidence store — saves screenshots, request/response pairs, PoC scripts
- [ ] Severity classifier — Critical/High/Medium/Low/Info based on impact
- [ ] Timeline logger — full chronological log of all actions taken

**Session 5 prompt for Claude Code:**
> "Build the Validator and Evidence Store for Noctis as defined in PLAN.md Phase 5. The validator replays each exploit finding to confirm reproducibility — if it fails on replay it is discarded. Add CVSS v3 scoring based on attack vector, complexity, privileges required, user interaction, and impact. Build an evidence store that saves: Playwright screenshots as PNG, raw HTTP request/response pairs as text, working PoC scripts as Python files, all organized by workspace ID and finding ID. Build a severity classifier that maps CVSS scores to Critical/High/Medium/Low/Info. Add a full timeline log of every action taken during the scan."

**Test:** Run a full scan on DVWA, confirm only reproducible findings kept with evidence files saved.

---

### PHASE 6 — Report Engine (Week 11-12)
**Goal:** Noctis generates professional client-ready reports.

**Deliverables:**
- [ ] PDF report — professional layout, executive summary, findings with evidence
- [ ] Markdown report — clean, editable, GitHub-friendly
- [ ] SARIF 2.1.0 output — standard format for CI/CD pipelines
- [ ] JSON output — raw findings data for integration
- [ ] Report includes: target info, scope, methodology, findings, PoC, remediation

**Session 6 prompt for Claude Code:**
> "Build the Report Engine for Noctis as defined in PLAN.md Phase 6. PDF report must include: cover page with target and date, executive summary, scope and methodology, findings table sorted by severity, detailed finding pages each with description/impact/PoC/evidence screenshots/remediation steps, and appendix with raw requests. Use WeasyPrint for PDF generation with a dark professional cyberpunk theme matching Noctis branding (dark background, red/cyan accents). Markdown report mirrors the PDF structure. SARIF output must be valid SARIF 2.1.0 format. JSON output contains all raw finding data. All reports saved to workspaces/{id}/reports/ folder."

**Test:** Generate PDF from a completed DVWA scan and review the output quality.

---

### PHASE 7 — Model Integration + Subscription Support (Week 13-14)
**Goal:** Noctis works with GPT Pro, Claude API, Gemini free, and OpenRouter.

**Deliverables:**
- [ ] Gemini API integration (free tier, development use)
- [ ] Claude API integration (pay per use, best quality)
- [ ] OpenAI API + Codex integration (GPT Pro subscription support)
- [ ] OpenRouter integration (fallback, model flexibility)
- [ ] Model performance benchmarking per agent type
- [ ] Cost tracker — estimates and logs API spend per scan
- [ ] Model fallback — if primary model fails, automatically tries next

**Session 7 prompt for Claude Code:**
> "Finalize the Model Router for Noctis as defined in PLAN.md Phase 7. Implement full support for: Gemini API via google-generativeai SDK, Claude API via anthropic SDK, OpenAI API via openai SDK with Codex subscription support, OpenRouter via OpenAI-compatible endpoint. Each provider must support streaming responses. Add a cost tracker that estimates token usage and cost per scan using each provider's pricing. Add automatic fallback — if primary model returns an error or rate limit, automatically retry with the next configured model. Add a model benchmark command: noctis benchmark --url https://testphp.vulnweb.com that runs all models and compares finding quality and cost."

**Test:** Run full scan with each model, compare findings and cost report.

---

### PHASE 8 — Hardening + Real Engagement Testing (Week 15-16)
**Goal:** Noctis is stable, safe, and ready for real client engagements.

**Deliverables:**
- [ ] Scope enforcement — hard block on any action outside defined scope
- [ ] Confirmation prompts for destructive actions
- [ ] Rate limiting — configurable requests per second to avoid detection/damage
- [ ] Error recovery — graceful handling of network errors, timeouts, crashes
- [ ] Resume from any pipeline stage after crash
- [ ] Full test suite — unit tests for all agents and engines
- [ ] Real engagement test — run against a client staging environment
- [ ] README and documentation

**Session 8 prompt for Claude Code:**
> "Harden Noctis for real professional use as defined in PLAN.md Phase 8. Add strict scope enforcement — before every HTTP request check it against the scope rules and hard-block if out of scope. Add rate limiting with configurable requests-per-second. Add confirmation prompts for any action that could cause damage (large sqlmap scans, brute force, etc) unless --no-confirm flag set. Add comprehensive error recovery — every stage should catch exceptions, log them, save state, and allow resume. Write unit tests for all exploitation agents using mocked HTTP responses. Add a --dry-run flag that shows what Noctis would do without actually doing it. Write a full README with installation, usage, model setup, and examples."

**Test:** Full real engagement on an authorized staging environment. Verify scope enforcement works.

---

### PHASE 9 — FastAPI Backend (Week 17-18)
**Goal:** Core engine exposed via REST API for Web UI integration.

**Deliverables:**
- [ ] FastAPI app wrapping the Noctis core engine
- [ ] WebSocket endpoint for real-time scan progress
- [ ] REST endpoints: start scan, pause, resume, list workspaces, get report
- [ ] Authentication for the API (JWT)
- [ ] Background task management for long-running scans

---

### PHASE 10 — Web Dashboard (Week 19-22)
**Goal:** Professional React dashboard for managing scans and viewing reports.

**Deliverables:**
- [ ] React + Vite + Tailwind frontend
- [ ] Cyberpunk dark theme matching Noctis branding
- [ ] Dashboard: active scans, past scans, findings overview
- [ ] Live scan view: real-time progress, agent activity, findings as they appear
- [ ] Report viewer: inline PDF/Markdown viewer
- [ ] Settings: model selection, API keys, default scope rules
- [ ] Fully self-hosted, runs locally via Docker Compose

---

## DEVELOPMENT RULES FOR CLAUDE CODE

These rules apply to every session:

1. **Read PLAN.md first** at the start of every session before writing any code
2. **One phase per session** — complete the current phase fully before moving on
3. **Test before moving on** — every phase has a test, run it and confirm it passes
4. **Never hardcode credentials** — always read from .env
5. **Scope enforcement is non-negotiable** — every HTTP request must be scope-checked
6. **Comments on every function** — future sessions need to understand the code
7. **Error handling everywhere** — no unhandled exceptions, everything logged
8. **Cross-platform** — code must run on Windows (dev) and Kali Linux (deployment)
9. **Model agnostic** — agents never call a model directly, always through model_router
10. **Git commit after each phase** — with descriptive commit message

---

## ENVIRONMENT VARIABLES (.env.example)

```env
# AI Model Configuration
GEMINI_API_KEY=your_gemini_key_here
OPENAI_API_KEY=your_openai_key_here
ANTHROPIC_API_KEY=your_anthropic_key_here
OPENROUTER_API_KEY=your_openrouter_key_here

# Default model (gemini | openai | claude | openrouter)
DEFAULT_MODEL=gemini

# Scan Configuration
MAX_WORKERS=3
REQUESTS_PER_SECOND=10
MAX_SCAN_DEPTH=5
CONFIRM_DESTRUCTIVE=true

# Reporting
REPORT_OUTPUT_DIR=./reports
WORKSPACE_DIR=./workspaces

# Optional: Interactsh for OOB callbacks (SSRF)
INTERACTSH_SERVER=oast.pro
```

---

## CLI COMMANDS REFERENCE

```bash
# Start a new scan
noctis scan --url https://target.com --repo /path/to/code --model gemini

# Scan with auth credentials
noctis scan --url https://target.com --auth-user admin --auth-pass password

# Scan with scope rules
noctis scan --url https://target.com --scope "only /api/*" --exclude "/api/delete*"

# Dry run (shows what it would do without doing it)
noctis scan --url https://target.com --dry-run

# Resume an interrupted scan
noctis resume --workspace abc123

# List all past scans
noctis workspaces list

# Generate report from completed scan
noctis report --workspace abc123 --format pdf
noctis report --workspace abc123 --format sarif
noctis report --workspace abc123 --format markdown

# Benchmark models
noctis benchmark --url https://testphp.vulnweb.com

# Show version
noctis --version
```

---

## MILESTONES

| Milestone | Phase | Target |
|---|---|---|
| CLI runs and creates workspace | Phase 1 | Week 2 |
| Full attack surface mapped | Phase 2 | Week 4 |
| Exploitation queue generated | Phase 3 | Week 6 |
| First real SQLi found autonomously | Phase 4 | Week 9 |
| First professional PDF report | Phase 6 | Week 12 |
| Real client engagement test | Phase 8 | Week 16 |
| Web dashboard live | Phase 10 | Week 22 |

---

## INSPIRATION & REFERENCES

- Shannon by Keygraph (github.com/KeygraphHQ/shannon) — architecture inspiration
- PentestGPT (github.com/GreyDGL/PentestGPT) — agent design inspiration
- Imperturbable — prompt engineering approach for CTF
- OWASP Testing Guide — vulnerability coverage checklist
- CVSS v3.1 — severity scoring standard

---

*This document is the single source of truth for the Noctis build.
Claude Code reads this at the start of every session.*
