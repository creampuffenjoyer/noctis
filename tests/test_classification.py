from noctis.validator.classification import classify


def test_sqli_maps_to_injection_and_initial_access():
    c = classify("sqli")
    assert c.owasp_category.startswith("A03:2021")
    assert "T1190" in c.attack_technique


def test_credential_exposure_maps_to_credential_access():
    c = classify("credential_exposure")
    assert c.owasp_category.startswith("A02:2021")
    assert "T1552" in c.attack_technique


def test_xxe_maps_to_security_misconfiguration():
    c = classify("xxe")
    assert c.owasp_category.startswith("A05:2021")


def test_auth_refines_by_evidence_jwt_none():
    c = classify("auth", evidence="server accepted a JWT with alg=none and an empty signature")
    assert "T1606" in c.attack_technique


def test_auth_refines_by_evidence_default_creds():
    c = classify("auth", evidence="default credentials 'admin:admin' were accepted")
    assert "T1110.001" in c.attack_technique


def test_auth_falls_back_without_matching_evidence():
    c = classify("auth", evidence="")
    assert "T1110" in c.attack_technique


def test_unknown_agent_type_falls_back():
    c = classify("nonexistent")
    assert c.owasp_category == "Uncategorized"
