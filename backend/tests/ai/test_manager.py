from typing import Any
from unittest.mock import patch

import pytest

from app.ai.manager import AIManager
from app.ai.provider import Prompt
from app.core.config import Settings
from app.core.exceptions import AIKeyRequiredException, UnsupportedProviderException


def _settings(**overrides: Any) -> Settings:
    defaults: dict[str, Any] = {
        "ai_provider": "huggingface",
        "huggingface_model": "org/test-model",
    }
    defaults.update(overrides)
    return Settings(_env_file=None, **defaults)


def test_resolve_provider_name_returns_configured_provider():
    assert AIManager(settings=_settings()).resolve_provider_name() == "huggingface"


def test_resolve_provider_name_rejects_unsupported_provider():
    manager = AIManager(settings=_settings(ai_provider="openrouter"))
    with pytest.raises(UnsupportedProviderException):
        manager.resolve_provider_name()


def test_resolve_model_name_returns_configured_model():
    manager = AIManager(
        settings=_settings(
            huggingface_model="meta-llama/Llama-3.1-8B-Instruct:cheapest"
        )
    )
    assert manager.resolve_model_name() == "meta-llama/Llama-3.1-8B-Instruct:cheapest"


def test_supported_providers_is_huggingface_only():
    assert AIManager.supported_providers() == ["huggingface"]


def test_generate_without_a_user_key_raises_key_required():
    manager = AIManager(settings=_settings(), api_key=None)
    assert not manager.has_key
    with pytest.raises(AIKeyRequiredException):
        manager.generate(Prompt(system="s", user="u"))
    with pytest.raises(AIKeyRequiredException):
        manager.check_key()


def test_generate_passes_the_user_key_to_the_provider():
    manager = AIManager(settings=_settings(), api_key="hf_user_key")
    with patch("app.ai.manager.HuggingFaceProvider") as provider_cls:
        _patched_registry_generate(manager, provider_cls)
    provider_cls.assert_called_once_with(manager.settings, "hf_user_key")


def _patched_registry_generate(manager: AIManager, provider_cls) -> None:
    with patch.dict("app.ai.manager._PROVIDER_REGISTRY", {"huggingface": provider_cls}):
        manager.generate(Prompt(system="s", user="u"))


def test_unsupported_provider_is_reported_before_the_key_check():
    manager = AIManager(settings=_settings(ai_provider="unknown"), api_key=None)
    with pytest.raises(UnsupportedProviderException):
        manager.generate(Prompt(system="s", user="u"))


@pytest.mark.parametrize(
    "model", ["no-slash", "org/model; rm -rf", "https://evil/x", "org/m:bad suffix"]
)
def test_invalid_model_ids_are_rejected(model):
    with pytest.raises(ValueError):
        _settings(huggingface_model=model)
