from noctis.validator.poc_generator import generate_poc_script


def test_runnable_script_for_poc_request():
    result = {
        "payload": "'",
        "evidence": "database error signature 'sql syntax' returned for param 'q'",
        "poc_request": {"method": "GET", "url": "https://example.com/search?q=%27", "data": None, "content": None},
    }
    script = generate_poc_script("sqli", "sqli_abc123", result)
    assert "httpx.request" in script
    assert "https://example.com/search?q=%27" in script
    assert "sqli_abc123" in script


def test_documentation_script_when_no_poc_request():
    result = {
        "payload": "<script>alert('x')</script>",
        "evidence": "confirmed JavaScript execution via param 'name' in a real browser",
        "request": "GET https://example.com/greet?name=x",
        "poc_request": None,
    }
    script = generate_poc_script("xss", "xss_def456", result)
    assert "httpx.request" not in script
    assert "real browser" in script
    assert "confirmed JavaScript execution" in script


def test_content_based_poc_request_uses_content_kwarg():
    result = {
        "payload": "<xml/>",
        "evidence": "XXE external entity resolved to a local file containing 'root:'",
        "poc_request": {"method": "POST", "url": "https://example.com/upload", "data": None, "content": "<xml/>"},
    }
    script = generate_poc_script("xxe", "xxe_ghi789", result)
    assert "content=" in script
