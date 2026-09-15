"""Maps each agent type to an OWASP Top 10 (2021) category and a MITRE
ATT&CK (Enterprise) tactic/technique, since both matter for how a red team
finding gets communicated and triaged.

Honest limitation on the ATT&CK side: our agents test a web app from the
outside, so nearly everything here is Initial Access via T1190 (Exploit
Public-Facing Application) -- the technique for "how did the attacker get
a foothold", not a full attack chain. ATT&CK is really built to describe
a multi-stage campaign (recon -> execution -> persistence -> lateral
movement -> exfiltration), and Noctis doesn't model post-exploitation yet
(see the README), so these tags describe the entry vector, not a kill
chain. `auth` and `credential_exposure` get more specific technique tags
because they map cleanly onto ATT&CK's Credential Access tactic regardless
of that limitation.

No CVE mapping here: a specific CVE identifies a known vulnerability in a
specific product/version. Noctis's findings are dynamically confirmed
against custom application logic, not matched against a CVE feed, so
attaching CVE IDs would be fabricated. `ValidatedFinding.cve_refs` exists
as a forward-compatible field but stays empty until a real CVE/NVD
correlation (e.g. against fingerprinted software + version) is built --
that's a distinct capability, not something to fake here.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Classification:
    owasp_category: str
    attack_tactic: str
    attack_technique: str


CLASSIFICATIONS: dict[str, Classification] = {
    "sqli": Classification(
        owasp_category="A03:2021 - Injection",
        attack_tactic="TA0001 - Initial Access",
        attack_technique="T1190 - Exploit Public-Facing Application",
    ),
    "xss": Classification(
        owasp_category="A03:2021 - Injection",
        attack_tactic="TA0001 - Initial Access",
        attack_technique="T1190 - Exploit Public-Facing Application",
    ),
    "ssrf": Classification(
        owasp_category="A10:2021 - Server-Side Request Forgery (SSRF)",
        attack_tactic="TA0001 - Initial Access",
        attack_technique="T1190 - Exploit Public-Facing Application",
    ),
    "idor": Classification(
        owasp_category="A01:2021 - Broken Access Control",
        attack_tactic="TA0001 - Initial Access",
        attack_technique="T1190 - Exploit Public-Facing Application",
    ),
    "rce": Classification(
        owasp_category="A03:2021 - Injection",
        attack_tactic="TA0002 - Execution",
        attack_technique="T1059 - Command and Scripting Interpreter (via T1190 Initial Access)",
    ),
    "lfi": Classification(
        owasp_category="A01:2021 - Broken Access Control",
        attack_tactic="TA0001 - Initial Access",
        attack_technique="T1190 - Exploit Public-Facing Application",
    ),
    "xxe": Classification(
        owasp_category="A05:2021 - Security Misconfiguration",
        attack_tactic="TA0001 - Initial Access",
        attack_technique="T1190 - Exploit Public-Facing Application",
    ),
    "credential_exposure": Classification(
        owasp_category="A02:2021 - Cryptographic Failures",
        attack_tactic="TA0006 - Credential Access",
        attack_technique="T1552.001 - Unsecured Credentials: Credentials In Files",
    ),
}

DEFAULT_CLASSIFICATION = Classification(
    owasp_category="Uncategorized",
    attack_tactic="TA0001 - Initial Access",
    attack_technique="T1190 - Exploit Public-Facing Application",
)

# auth spans several distinct techniques depending on which check fired;
# refined at runtime from the finding's evidence text rather than forced
# into one tag.
_AUTH_REFINEMENTS: list[tuple[str, Classification]] = [
    (
        "alg=none",
        Classification(
            owasp_category="A07:2021 - Identification and Authentication Failures",
            attack_tactic="TA0006 - Credential Access",
            attack_technique="T1606.001 - Forge Web Credentials: Web Cookies",
        ),
    ),
    (
        "weak/common secret",
        Classification(
            owasp_category="A07:2021 - Identification and Authentication Failures",
            attack_tactic="TA0006 - Credential Access",
            attack_technique="T1606.001 - Forge Web Credentials: Web Cookies",
        ),
    ),
    (
        "session identifier was not rotated",
        Classification(
            owasp_category="A07:2021 - Identification and Authentication Failures",
            attack_tactic="TA0006 - Credential Access",
            attack_technique="T1539 - Steal Web Session Cookie (session fixation, no dedicated ATT&CK technique)",
        ),
    ),
    (
        "default credentials",
        Classification(
            owasp_category="A07:2021 - Identification and Authentication Failures",
            attack_tactic="TA0006 - Credential Access",
            attack_technique="T1110.001 - Brute Force: Password Guessing",
        ),
    ),
]
_AUTH_DEFAULT = Classification(
    owasp_category="A07:2021 - Identification and Authentication Failures",
    attack_tactic="TA0006 - Credential Access",
    attack_technique="T1110 - Brute Force",
)


def classify(agent_type: str, evidence: str = "") -> Classification:
    if agent_type == "auth":
        lowered = evidence.lower()
        for needle, classification in _AUTH_REFINEMENTS:
            if needle in lowered:
                return classification
        return _AUTH_DEFAULT
    return CLASSIFICATIONS.get(agent_type, DEFAULT_CLASSIFICATION)
