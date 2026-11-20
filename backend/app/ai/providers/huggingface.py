"""Hugging Face Inference Providers adapter (OpenAI-compatible chat API).

Endpoint and auth per https://huggingface.co/docs/inference-providers:
POST https://router.huggingface.co/v1/chat/completions with
`Authorization: Bearer <user token>`; the text is at
choices[0].message.content. The token needs the fine-grained
"Make calls to Inference Providers" permission.
"""

import logging

import httpx

from app.ai.provider import AIProviderInterface, AIProviderResponse, Prompt
from app.core.config import Settings
from app.core.exceptions import AIProviderException

logger = logging.getLogger(__name__)

PROVIDER_NAME = "huggingface"
# Fixed, not configurable: the user's key is only ever sent to this host.
BASE_URL = "https://router.huggingface.co/v1"

_STATUS_MESSAGES = {
    401: "Hugging Face rejected the API key. Check the key on your Profile page.",
    402: "Your Hugging Face account has no inference credits left.",
    403: "This Hugging Face key is not allowed to call Inference Providers.",
    404: "The configured Hugging Face model is not available.",
    429: "Hugging Face rate limit reached. Try again shortly.",
}


class HuggingFaceProvider(AIProviderInterface):
    """Calls one chat model with the requesting user's own key."""

    def __init__(self, settings: Settings, api_key: str):
        self._api_key = api_key
        self._model = settings.huggingface_model
        self._timeout = settings.ai_request_timeout_seconds
        self._max_tokens = settings.ai_max_tokens

    def generate(self, prompt: Prompt) -> AIProviderResponse:
        content = self._chat(
            [
                {"role": "system", "content": prompt.system},
                {"role": "user", "content": prompt.user},
            ],
            max_tokens=self._max_tokens,
        )
        if not content.strip():
            raise AIProviderException("AI provider returned an empty response.")
        return AIProviderResponse(
            content=content, provider=PROVIDER_NAME, model=self._model
        )

    def check_key(self) -> None:
        """Make the smallest possible call to prove the key works.

        This spends a negligible amount of inference credit; Hugging Face
        documents no free token-validation endpoint for Inference Providers.
        """
        self._chat([{"role": "user", "content": "ping"}], max_tokens=1)

    def _chat(self, messages: list[dict[str, str]], max_tokens: int) -> str:
        try:
            response = httpx.post(
                f"{BASE_URL}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self._model,
                    "messages": messages,
                    "max_tokens": max_tokens,
                },
                timeout=self._timeout,
                follow_redirects=False,
            )
        except httpx.TimeoutException as exc:
            logger.error(
                "Hugging Face request timed out",
                extra={"context": {"provider": PROVIDER_NAME, "model": self._model}},
            )
            raise AIProviderException("AI provider request timed out.") from exc
        except httpx.RequestError as exc:
            logger.error(
                "Hugging Face request failed",
                extra={"context": {"provider": PROVIDER_NAME, "model": self._model}},
            )
            raise AIProviderException("Failed to reach the AI provider.") from exc

        if response.status_code >= 400:
            logger.warning(
                "Hugging Face returned a non-success response",
                extra={
                    "context": {
                        "provider": PROVIDER_NAME,
                        "model": self._model,
                        "status_code": response.status_code,
                    }
                },
            )
            raise AIProviderException(
                _STATUS_MESSAGES.get(
                    response.status_code,
                    f"AI provider returned an error status: {response.status_code}.",
                )
            )

        try:
            content = response.json()["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise AIProviderException(
                "AI provider returned a malformed response."
            ) from exc
        return content if isinstance(content, str) else ""
