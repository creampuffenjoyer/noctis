from types import SimpleNamespace

import pytest

from noctis.config.settings import ModelProvider, Settings
from noctis.core.model_router import ModelRouter, ModelRouterError


def _settings(tmp_path, **overrides) -> Settings:
    return Settings(workspace_dir=tmp_path / "workspaces", _env_file=None, **overrides)


class _FakeCompletions:
    def __init__(self, content: str):
        self.content = content
        self.calls: list[dict] = []

    async def create(self, model, messages):
        self.calls.append({"model": model, "messages": messages})
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=self.content))])


class _FakeAsyncOpenAI:
    """Stands in for openai.AsyncOpenAI so tests never touch the network --
    pytest-httpx doesn't reliably intercept the SDK's own transport setup,
    so we mock at the SDK boundary instead.
    """

    last_instance: "_FakeAsyncOpenAI | None" = None

    def __init__(self, api_key=None, base_url=None):
        self.api_key = api_key
        self.base_url = base_url
        self.chat = SimpleNamespace(completions=_FakeCompletions("PONG"))
        _FakeAsyncOpenAI.last_instance = self


@pytest.mark.asyncio
async def test_local_provider_calls_configured_endpoint(tmp_path, monkeypatch):
    monkeypatch.setattr("openai.AsyncOpenAI", _FakeAsyncOpenAI)
    settings = _settings(
        tmp_path,
        local_base_url="http://localhost:11434/v1",
        local_model_name="huihui_ai/qwen3.5-abliterated:9b",
    )

    router = ModelRouter(settings)
    result = await router.think("ping", provider=ModelProvider.LOCAL)

    assert result.text == "PONG"
    assert result.provider == ModelProvider.LOCAL
    assert result.model == "huihui_ai/qwen3.5-abliterated:9b"
    assert _FakeAsyncOpenAI.last_instance.base_url == "http://localhost:11434/v1"
    assert _FakeAsyncOpenAI.last_instance.chat.completions.calls[0]["model"] == "huihui_ai/qwen3.5-abliterated:9b"


@pytest.mark.asyncio
async def test_local_provider_never_reports_missing_api_key(tmp_path):
    # local_api_key defaults to a non-empty placeholder so the generic
    # "no API key configured" guard never fires for a provider that doesn't
    # need a real one
    settings = _settings(tmp_path)
    assert settings.api_key_for(ModelProvider.LOCAL)


@pytest.mark.asyncio
async def test_model_names_override_takes_precedence(tmp_path, monkeypatch):
    monkeypatch.setattr("openai.AsyncOpenAI", _FakeAsyncOpenAI)
    settings = _settings(tmp_path)

    router = ModelRouter(settings, model_names={ModelProvider.LOCAL: "custom-tag"})
    result = await router.think("ping", provider=ModelProvider.LOCAL)

    assert result.model == "custom-tag"
    assert _FakeAsyncOpenAI.last_instance.chat.completions.calls[0]["model"] == "custom-tag"


@pytest.mark.asyncio
async def test_missing_key_provider_raises_clear_error(tmp_path):
    settings = _settings(tmp_path, openai_api_key=None)
    router = ModelRouter(settings)

    with pytest.raises(ModelRouterError, match="No API key configured"):
        await router.think("ping", provider=ModelProvider.OPENAI)


@pytest.mark.asyncio
async def test_provider_call_failure_wrapped_in_router_error(tmp_path, monkeypatch):
    class _BrokenCompletions:
        async def create(self, model, messages):
            raise RuntimeError("connection refused")

    class _BrokenAsyncOpenAI:
        def __init__(self, api_key=None, base_url=None):
            self.chat = SimpleNamespace(completions=_BrokenCompletions())

    monkeypatch.setattr("openai.AsyncOpenAI", _BrokenAsyncOpenAI)
    settings = _settings(tmp_path)
    router = ModelRouter(settings)

    with pytest.raises(ModelRouterError, match="local call failed"):
        await router.think("ping", provider=ModelProvider.LOCAL)
