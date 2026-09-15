"""CVSS v3.1 base score calculator, implementing the official formula (not an
approximation) against a heuristic default vector per agent type. There's no
human assessor in the loop, so these vectors are a documented, adjustable
starting point, not a claim of certainty -- see DEFAULT_VECTORS.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Any

AV_VALUES = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC_VALUES = {"L": 0.77, "H": 0.44}
PR_VALUES_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_VALUES_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
UI_VALUES = {"N": 0.85, "R": 0.62}
CIA_VALUES = {"N": 0.0, "L": 0.22, "H": 0.56}

SEVERITY_THRESHOLDS = [(9.0, "Critical"), (7.0, "High"), (4.0, "Medium"), (0.1, "Low")]


@dataclass(frozen=True)
class CvssVector:
    av: str  # Attack Vector: N/A/L/P
    ac: str  # Attack Complexity: L/H
    pr: str  # Privileges Required: N/L/H
    ui: str  # User Interaction: N/R
    scope: str  # S: U (unchanged) / C (changed)
    c: str  # Confidentiality impact: N/L/H
    i: str  # Integrity impact: N/L/H
    a: str  # Availability impact: N/L/H

    def to_vector_string(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.av}/AC:{self.ac}/PR:{self.pr}/UI:{self.ui}"
            f"/S:{self.scope}/C:{self.c}/I:{self.i}/A:{self.a}"
        )


def _roundup(value: float) -> float:
    """CVSS's official round-up-to-1-decimal, not plain rounding (avoids
    float precision issues per the spec's own reference implementation).
    """
    int_value = round(value * 100000)
    if int_value % 10000 == 0:
        return int_value / 100000.0
    return (int_value // 10000 + 1) / 10.0


def base_score(vector: CvssVector) -> float:
    isc_base = 1 - (1 - CIA_VALUES[vector.c]) * (1 - CIA_VALUES[vector.i]) * (1 - CIA_VALUES[vector.a])

    if vector.scope == "U":
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15

    if impact <= 0:
        return 0.0

    pr_values = PR_VALUES_UNCHANGED if vector.scope == "U" else PR_VALUES_CHANGED
    exploitability = 8.22 * AV_VALUES[vector.av] * AC_VALUES[vector.ac] * pr_values[vector.pr] * UI_VALUES[vector.ui]

    if vector.scope == "U":
        return _roundup(min(impact + exploitability, 10.0))
    return _roundup(min(1.08 * (impact + exploitability), 10.0))


def severity_for(score: float) -> str:
    if score <= 0:
        return "Info"
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "Info"


# Heuristic default vector per agent type: a reasonable, typical-case starting
# point for that vulnerability class over the network, not a per-finding human
# assessment. Adjusted per-node below when we have signal (e.g. auth_required).
DEFAULT_VECTORS: dict[str, CvssVector] = {
    "sqli": CvssVector(av="N", ac="L", pr="N", ui="N", scope="U", c="H", i="H", a="H"),
    "xss": CvssVector(av="N", ac="L", pr="N", ui="R", scope="C", c="L", i="L", a="N"),
    "ssrf": CvssVector(av="N", ac="L", pr="N", ui="N", scope="C", c="H", i="L", a="N"),
    "auth": CvssVector(av="N", ac="L", pr="N", ui="N", scope="U", c="H", i="H", a="N"),
    "idor": CvssVector(av="N", ac="L", pr="L", ui="N", scope="U", c="H", i="N", a="N"),
    "rce": CvssVector(av="N", ac="L", pr="N", ui="N", scope="U", c="H", i="H", a="H"),
    "lfi": CvssVector(av="N", ac="L", pr="N", ui="N", scope="U", c="H", i="N", a="N"),
    "xxe": CvssVector(av="N", ac="L", pr="N", ui="N", scope="U", c="H", i="L", a="L"),
    "credential_exposure": CvssVector(av="N", ac="L", pr="N", ui="N", scope="U", c="H", i="H", a="N"),
}
DEFAULT_FALLBACK_VECTOR = CvssVector(av="N", ac="L", pr="N", ui="N", scope="U", c="L", i="L", a="N")


def vector_for(agent_type: str, node_data: dict[str, Any]) -> CvssVector:
    vector = DEFAULT_VECTORS.get(agent_type, DEFAULT_FALLBACK_VECTOR)
    # auth_required is currently always False from Phase 2 recon (it isn't
    # inferred yet), so this branch is correct but dormant until that lands.
    if node_data.get("auth_required") and vector.pr == "N":
        vector = dataclasses.replace(vector, pr="L")
    return vector
