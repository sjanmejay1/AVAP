"""AI Provider Manager: resolves the configured provider and routes requests to it.

Business logic (the AI Service) depends only on this manager and the
provider-neutral types in app.ai.provider, never on a concrete provider.
Each manager carries the key of the user the work is done for; there is no
server-wide fallback key.
"""

from app.ai.provider import AIProviderInterface, AIProviderResponse, Prompt
from app.ai.providers.huggingface import HuggingFaceProvider
from app.core.config import Settings, get_settings
from app.core.exceptions import AIKeyRequiredException, UnsupportedProviderException

# Registry of supported providers and the settings field naming their model.
# Adding a provider requires only a new entry here and a new adapter under
# app/ai/providers/, with no change to business logic.
_PROVIDER_REGISTRY: dict[str, type[AIProviderInterface]] = {
    "huggingface": HuggingFaceProvider,
}
_PROVIDER_MODEL_SETTING: dict[str, str] = {
    "huggingface": "huggingface_model",
}


class AIManager:
    """Resolves the configured AI provider and executes generation requests."""

    def __init__(self, settings: Settings | None = None, api_key: str | None = None):
        self.settings = settings or get_settings()
        self._api_key = api_key

    @property
    def has_key(self) -> bool:
        """Whether a user key is available for provider calls."""
        return bool(self._api_key)

    @staticmethod
    def supported_providers() -> list[str]:
        """Return the names of all currently implemented AI providers."""
        return sorted(_PROVIDER_REGISTRY.keys())

    def resolve_provider_name(self) -> str:
        """Return the configured provider name, validating it is supported."""
        provider_name = self.settings.ai_provider
        if provider_name not in _PROVIDER_REGISTRY:
            raise UnsupportedProviderException(
                f"Unsupported AI provider configured: '{provider_name}'."
            )
        return provider_name

    def resolve_model_name(self) -> str:
        """Return the configured model name for the active provider."""
        provider_name = self.resolve_provider_name()
        setting_name = _PROVIDER_MODEL_SETTING[provider_name]
        return str(getattr(self.settings, setting_name))

    def generate(self, prompt: Prompt) -> AIProviderResponse:
        """Invoke the configured provider and return its provider-neutral result.

        Raises:
            AIKeyRequiredException: if the user has no key for the provider.
        """
        return self._provider().generate(prompt)

    def check_key(self) -> None:
        """Verify the user's key with the provider."""
        self._provider().check_key()

    def _provider(self) -> AIProviderInterface:
        provider_name = self.resolve_provider_name()
        if not self._api_key:
            raise AIKeyRequiredException(provider_name)
        return _PROVIDER_REGISTRY[provider_name](self.settings, self._api_key)
