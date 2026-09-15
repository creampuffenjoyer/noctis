from noctis.validator.cvss import CvssVector, base_score, severity_for, vector_for


def test_known_reference_vector_scores_9_8():
    # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H is a well-known 9.8 reference vector
    vector = CvssVector(av="N", ac="L", pr="N", ui="N", scope="U", c="H", i="H", a="H")
    assert base_score(vector) == 9.8


def test_no_impact_scores_zero():
    vector = CvssVector(av="N", ac="L", pr="N", ui="N", scope="U", c="N", i="N", a="N")
    assert base_score(vector) == 0.0


def test_scope_changed_xss_style_vector_scores_medium():
    vector = CvssVector(av="N", ac="L", pr="N", ui="R", scope="C", c="L", i="L", a="N")
    score = base_score(vector)
    assert 5.5 <= score <= 6.5


def test_severity_buckets():
    assert severity_for(9.8) == "Critical"
    assert severity_for(7.0) == "High"
    assert severity_for(6.9) == "Medium"
    assert severity_for(4.0) == "Medium"
    assert severity_for(3.9) == "Low"
    assert severity_for(0.1) == "Low"
    assert severity_for(0.0) == "Info"


def test_vector_for_bumps_privileges_when_auth_required():
    vector = vector_for("idor", {"auth_required": True})
    assert vector.pr == "L"  # idor's default pr is already L, stays L (no N to bump)

    vector = vector_for("sqli", {"auth_required": True})
    assert vector.pr == "L"  # sqli defaults to N, bumped to L

    vector = vector_for("sqli", {"auth_required": False})
    assert vector.pr == "N"


def test_vector_for_unknown_agent_type_falls_back():
    vector = vector_for("nonexistent", {})
    assert vector.c == "L"
