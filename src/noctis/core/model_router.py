"""Model router: single abstraction over Gemini, OpenAI, Claude, and OpenRouter.

Agents and engines must never call a model SDK directly — always go through
ModelRouter.think(). Provider SDKs are imported lazily so a machine with only
one provider configured never has to install/import the others.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from noctis.config.settings import ModelProvider, Settings, get_settings

logger = logging.getLogger("noctis.model_router")

DEFAULT_MODEL_NAMES: dict[ModelProvider, str] = {
    ModelProvider.GEMINI: "gemini-2.5-flash",
    ModelProvider.OPENAI: "gpt-4.1",
    ModelProvider.CLAUDE: "claude-sonnet-5",
    ModelProvider.OPENROUTER: "openrouter/auto",
}


class ModelRouterError(RuntimeError):
    """Raised when a provider call fails or is misconfigured."""


@dataclass
class ThinkResult:
    text: str
    provider: ModelProvider
    model: str
    raw: object = None


class ModelRouter:
    """Unified interface: `await router.think(prompt, context)`."""

    def __init__(self, settings: Settings | None = None, *, model_names: dict[ModelProvider, str] | None = None):
        self.settings = settings or get_settings()
        self.model_names = {**DEFAULT_MODEL_NAMES, **(model_names or {})}

    async def think(
        self,
        prompt: str,
        context: str | None = None,
        *,
        provider: ModelProvider | None = None,
        system: str | None = None,
    ) -> ThinkResult:
        provider = provider or self.settings.default_model
        api_key = self.settings.api_key_for(provider)
        if not api_key:
            raise ModelRouterError(
                f"No API key configured for provider '{provider.value}'. "
                f"Set the matching key in .env."
            )

        full_prompt = f"{context}\n\n{prompt}" if context else prompt
        handler = {
            ModelProvider.GEMINI: self._call_gemini,
            ModelProvider.OPENAI: self._call_openai,
            ModelProvider.CLAUDE: self._call_claude,
            ModelProvider.OPENROUTER: self._call_openrouter,
        }[provider]

        logger.debug("model_router: calling %s (model=%s)", provider.value, self.model_names[provider])
        try:
            return await handler(full_prompt, api_key, system)
        except ModelRouterError:
            raise
        except Exception as exc:  # provider SDKs raise their own exception types
            raise ModelRouterError(f"{provider.value} call failed: {exc}") from exc

    async def _call_gemini(self, prompt: str, api_key: str, system: str | None) -> ThinkResult:
        import asyncio

        import google.generativeai as genai

        genai.configure(api_key=api_key)
        model_name = self.model_names[ModelProvider.GEMINI]
        model = genai.GenerativeModel(model_name, system_instruction=system)
        response = await asyncio.to_thread(model.generate_content, prompt)
        return ThinkResult(text=response.text, provider=ModelProvider.GEMINI, model=model_name, raw=response)

    async def _call_openai(self, prompt: str, api_key: str, system: str | None) -> ThinkResult:
        from openai import AsyncOpenAI

        client = AsyncOpenAI(api_key=api_key)
        model_name = self.model_names[ModelProvider.OPENAI]
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        response = await client.chat.completions.create(model=model_name, messages=messages)
        return ThinkResult(
            text=response.choices[0].message.content or "",
            provider=ModelProvider.OPENAI,
            model=model_name,
            raw=response,
        )

    async def _call_claude(self, prompt: str, api_key: str, system: str | None) -> ThinkResult:
        from anthropic import AsyncAnthropic

        client = AsyncAnthropic(api_key=api_key)
        model_name = self.model_names[ModelProvider.CLAUDE]
        response = await client.messages.create(
            model=model_name,
            max_tokens=4096,
            system=system or "",
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(block.text for block in response.content if block.type == "text")
        return ThinkResult(text=text, provider=ModelProvider.CLAUDE, model=model_name, raw=response)

    async def _call_openrouter(self, prompt: str, api_key: str, system: str | None) -> ThinkResult:
        from openai import AsyncOpenAI

        client = AsyncOpenAI(api_key=api_key, base_url="https://openrouter.ai/api/v1")
        model_name = self.model_names[ModelProvider.OPENROUTER]
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        response = await client.chat.completions.create(model=model_name, messages=messages)
        return ThinkResult(
            text=response.choices[0].message.content or "",
            provider=ModelProvider.OPENROUTER,
            model=model_name,
            raw=response,
        )
