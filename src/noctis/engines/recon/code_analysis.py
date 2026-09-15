"""Code analysis agent: parses a local repo, maps routes to files, traces user input
to dangerous sinks, and scans for hardcoded secrets.

This is static/regex-based pattern matching, not a full AST/taint analysis —
good enough to prioritize where the exploitation agents should look first.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
    ".next", "vendor", "target", ".mypy_cache", ".pytest_cache",
}

SOURCE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".java", ".rb", ".go"}

# category -> list of (language extension globs, regex)
SINK_PATTERNS: dict[str, list[re.Pattern]] = {
    "sql": [
        re.compile(r"""(?:execute|cursor\.execute|query)\s*\(\s*[^)]*%s"""),
        re.compile(r"""(?:execute|query)\s*\(\s*f['"]"""),
        re.compile(r"""(?:execute|query)\s*\([^)]*\+\s*\w+"""),
        re.compile(r"""\$wpdb->query\s*\("""),
    ],
    "command_exec": [
        re.compile(r"""\bos\.system\s*\("""),
        re.compile(r"""\bsubprocess\.(?:run|call|Popen|check_output)\s*\("""),
        re.compile(r"""\bexec\s*\("""),
        re.compile(r"""\bchild_process\.(?:exec|execSync|spawn)\s*\("""),
        re.compile(r"""\bshell_exec\s*\("""),
        re.compile(r"""\bRuntime\.getRuntime\(\)\.exec\s*\("""),
    ],
    "eval": [
        re.compile(r"""\beval\s*\("""),
        re.compile(r"""\bnew\s+Function\s*\("""),
        re.compile(r"""\bpickle\.loads\s*\("""),
        re.compile(r"""\byaml\.load\s*\((?!.*Loader=yaml\.SafeLoader)"""),
    ],
    "file_ops": [
        re.compile(r"""\bopen\s*\([^)]*request\."""),
        re.compile(r"""\bfs\.readFile\w*\s*\("""),
        re.compile(r"""\binclude(?:_once)?\s*\(\s*\$_"""),
        re.compile(r"""\brequire(?:_once)?\s*\(\s*\$_"""),
    ],
    "render": [
        re.compile(r"""render_template_string\s*\("""),
        re.compile(r"""dangerouslySetInnerHTML"""),
        re.compile(r"""\.innerHTML\s*="""),
        re.compile(r"""response\.write\s*\([^)]*req\."""),
    ],
}

SECRET_PATTERNS: dict[str, re.Pattern] = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(r"""(?i)aws_secret_access_key\s*[=:]\s*['"][A-Za-z0-9/+=]{40}['"]"""),
    "generic_api_key": re.compile(r"""(?i)\b(?:api[_-]?key|secret|token)\b\s*[=:]\s*['"][A-Za-z0-9_\-]{16,}['"]"""),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
}

ROUTE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("flask", re.compile(r"""@app\.route\s*\(\s*['"]([^'"]+)['"](?:.*methods\s*=\s*\[([^\]]*)\])?""")),
    ("fastapi", re.compile(r"""@\w+\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]""")),
    ("express", re.compile(r"""\w+\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]""")),
    ("django", re.compile(r"""path\s*\(\s*['"]([^'"]*)['"]""")),
]


@dataclass
class Sink:
    file: str
    line: int
    category: str
    snippet: str

    def to_dict(self) -> dict:
        return {"file": self.file, "line": self.line, "category": self.category, "snippet": self.snippet}


@dataclass
class Route:
    method: str
    path: str
    file: str
    line: int
    framework: str

    def to_dict(self) -> dict:
        return {"method": self.method, "path": self.path, "file": self.file, "line": self.line, "framework": self.framework}


@dataclass
class Secret:
    file: str
    line: int
    kind: str
    masked_value: str

    def to_dict(self) -> dict:
        return {"file": self.file, "line": self.line, "kind": self.kind, "masked_value": self.masked_value}


@dataclass
class CodeAnalysisResult:
    repo_path: str
    files_scanned: int = 0
    routes: list[Route] = field(default_factory=list)
    sinks: list[Sink] = field(default_factory=list)
    secrets: list[Secret] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "repo_path": self.repo_path,
            "files_scanned": self.files_scanned,
            "routes": [r.to_dict() for r in self.routes],
            "sinks": [s.to_dict() for s in self.sinks],
            "secrets": [s.to_dict() for s in self.secrets],
        }


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def _iter_source_files(repo_path: Path):
    for path in repo_path.rglob("*"):
        if not path.is_file() or path.suffix not in SOURCE_EXTENSIONS:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path


def analyze_repo(repo_path: str) -> CodeAnalysisResult:
    root = Path(repo_path).resolve()
    result = CodeAnalysisResult(repo_path=str(root))

    for file_path in _iter_source_files(root):
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        result.files_scanned += 1
        rel_path = str(file_path.relative_to(root))
        lines = text.splitlines()

        for lineno, line in enumerate(lines, start=1):
            for category, patterns in SINK_PATTERNS.items():
                for pattern in patterns:
                    if pattern.search(line):
                        result.sinks.append(Sink(file=rel_path, line=lineno, category=category, snippet=line.strip()[:200]))
                        break

            for kind, pattern in SECRET_PATTERNS.items():
                match = pattern.search(line)
                if match:
                    result.secrets.append(Secret(file=rel_path, line=lineno, kind=kind, masked_value=_mask(match.group(0))))

            if file_path.suffix == ".py" and "@app.route" in line:
                _match_route(rel_path, lineno, line, result)
            elif file_path.suffix in (".js", ".ts") and re.search(r"""\.(get|post|put|delete|patch)\s*\(""", line):
                _match_route(rel_path, lineno, line, result)
            elif file_path.suffix == ".py" and "path(" in line:
                _match_route(rel_path, lineno, line, result)

    return result


def _match_route(rel_path: str, lineno: int, line: str, result: CodeAnalysisResult) -> None:
    for framework, pattern in ROUTE_PATTERNS:
        match = pattern.search(line)
        if not match:
            continue
        groups = match.groups()
        if framework == "flask":
            path, methods = groups[0], groups[1]
            method = methods.split(",")[0].strip().strip("'\"") if methods else "GET"
            result.routes.append(Route(method=method, path=path, file=rel_path, line=lineno, framework=framework))
        elif framework in ("fastapi", "express"):
            method, path = groups[0], groups[1]
            result.routes.append(Route(method=method.upper(), path=path, file=rel_path, line=lineno, framework=framework))
        elif framework == "django":
            path = groups[0]
            result.routes.append(Route(method="ANY", path=path, file=rel_path, line=lineno, framework=framework))
        return
