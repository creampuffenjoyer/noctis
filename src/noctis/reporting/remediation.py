"""Remediation guidance per vulnerability class. Standard, well-established
advice for the class (OWASP Cheat Sheet Series style), not tailored to the
specific application -- a starting point for the tester/developer, same
spirit as the heuristic CVSS vectors in the Validator.
"""
from __future__ import annotations

REMEDIATION: dict[str, str] = {
    "sqli": (
        "Use parameterized queries or prepared statements (or an ORM that does this for you) instead of "
        "building SQL with string concatenation. Apply least-privilege database accounts so even a successful "
        "injection has limited reach."
    ),
    "xss": (
        "Apply context-aware output encoding for all user-controlled data rendered into HTML, JS, or attribute "
        "contexts. Set a strict Content-Security-Policy. Prefer frameworks with automatic escaping (React, Vue, "
        "Jinja2 autoescape) over manual string building."
    ),
    "ssrf": (
        "Validate and allow-list outbound destinations server-side. Block requests to link-local "
        "(169.254.0.0/16), loopback, and RFC1918 ranges unless explicitly required. Use an egress proxy/firewall "
        "as defense in depth."
    ),
    "auth": (
        "Verify JWT signatures against an explicit allow-listed algorithm and never accept 'none'. Use a strong, "
        "sufficiently random signing secret (or asymmetric keys). Rotate session identifiers on privilege change. "
        "Rate-limit and lock out repeated failed logins, and remove default credentials before deployment."
    ),
    "idor": (
        "Enforce object-level authorization on every request -- verify the authenticated user is permitted to "
        "access the specific referenced resource, not just that they're authenticated. Prefer indirect, "
        "per-user references over sequential or guessable IDs where practical."
    ),
    "rce": (
        "Never pass user input to a shell or interpreter. Use parameterized APIs (e.g. subprocess with an "
        "argument list, not shell=True) with strict input allow-lists. Sandbox or run with least privilege if "
        "dynamic execution is unavoidable."
    ),
    "lfi": (
        "Never build file paths directly from user input. Resolve to a canonical path and verify it stays within "
        "an allowed base directory, rejecting traversal sequences. Prefer an indirect mapping (id -> filename) "
        "over raw user-supplied paths."
    ),
    "xxe": (
        "Disable external entity and DTD processing in the XML parser (e.g. via defusedxml, or explicit parser "
        "flags). Prefer a data format that doesn't support entities, such as JSON, where possible."
    ),
    "credential_exposure": (
        "Treat the exposed credential as compromised: rotate it immediately and remove it from source control "
        "history. Load secrets from an environment variable or a secrets manager instead, and add the pattern "
        "to a pre-commit secret scanner to catch recurrences."
    ),
}
