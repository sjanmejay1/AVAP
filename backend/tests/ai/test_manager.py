from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.ai.manager import AIManager
from app.ai.provider import Prompt
from app.core.config import Settings
from app.core.exceptions import AIKeyRequiredException, UnsupportedProviderException


def _settings(**overrides: Any) -> Settings:
    defaults: dict[str, Any] = {
        "ai_provider": "openrouter",
        "openrouter_model": "org/test-model:free",
    }
    defaults.update(overrides)
    return Settings(_env_file=None, **defaults)


def test_resolve_provider_name_returns_configured_provider():
    assert AIManager(settings=_settings()).resolve_provider_name() == "openrouter"


def test_resolve_provider_name_rejects_unsupported_provider():
    manager = AIManager(settings=_settings(ai_provider="huggingface"))
    with pytest.raises(UnsupportedProviderException):
        manager.resolve_provider_name()


def test_resolve_model_name_returns_configured_model():
    manager = AIManager(settings=_settings(openrouter_model="openrouter/free"))
    assert manager.resolve_model_name() == "openrouter/free"


def test_supported_providers_is_openrouter_only():
    assert AIManager.supported_providers() == ["openrouter"]


def test_generate_without_a_user_key_raises_key_required():
    manager = AIManager(settings=_settings(), api_key=None)
    assert not manager.has_key
    with pytest.raises(AIKeyRequiredException):
        manager.generate(Prompt(system="s", user="u"))
    with pytest.raises(AIKeyRequiredException):
        manager.check_key()


def test_generate_passes_the_user_key_to_the_provider():
    manager = AIManager(settings=_settings(), api_key="sk-or-user-key")
    provider_cls = MagicMock()
    with patch.dict("app.ai.manager._PROVIDER_REGISTRY", {"openrouter": provider_cls}):
        manager.generate(Prompt(system="s", user="u"))
    provider_cls.assert_called_once_with(manager.settings, "sk-or-user-key")


def test_unsupported_provider_is_reported_before_the_key_check():
    manager = AIManager(settings=_settings(ai_provider="unknown"), api_key=None)
    with pytest.raises(UnsupportedProviderException):
        manager.generate(Prompt(system="s", user="u"))


@pytest.mark.parametrize(
    "model",
    [
        "openai/gpt-4o",
        "meta-llama/llama-3.3-70b-instruct",
        "org/model:nitro",
        "openrouter/auto",
        "no-slash:free",
        "org/model; rm -rf:free",
    ],
)
def test_paid_or_malformed_models_are_refused(model):
    with pytest.raises(ValueError, match="free model"):
        _settings(openrouter_model=model)


@pytest.mark.parametrize("model", ["google/gemma-4-31b-it:free", "openrouter/free"])
def test_free_models_are_accepted(model):
    assert _settings(openrouter_model=model).openrouter_model == model


def test_data_collection_policy_is_validated():
    assert _settings(openrouter_data_collection="DENY").openrouter_data_collection == (
        "deny"
    )
    with pytest.raises(ValueError):
        _settings(openrouter_data_collection="sometimes")
