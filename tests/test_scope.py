from noctis.core.scope import ScopeEngine, ScopeViolationError

import pytest


def test_same_host_in_scope_by_default():
    scope = ScopeEngine(target="https://example.com")
    assert scope.is_in_scope("https://example.com/anything")


def test_different_host_out_of_scope():
    scope = ScopeEngine(target="https://example.com")
    assert not scope.is_in_scope("https://evil.com/")


def test_exclude_pattern_blocks_path():
    scope = ScopeEngine(target="https://example.com", exclude=["/api/delete*"])
    assert scope.is_in_scope("https://example.com/api/list")
    assert not scope.is_in_scope("https://example.com/api/delete/1")


def test_include_pattern_restricts_scope():
    scope = ScopeEngine(target="https://example.com", include=["/api/*"])
    assert scope.is_in_scope("https://example.com/api/list")
    assert not scope.is_in_scope("https://example.com/admin")


def test_assert_in_scope_raises_on_violation():
    scope = ScopeEngine(target="https://example.com")
    with pytest.raises(ScopeViolationError):
        scope.assert_in_scope("https://evil.com/")
