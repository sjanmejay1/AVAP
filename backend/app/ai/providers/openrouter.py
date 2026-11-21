"""OpenRouter adapter (OpenAI-compatible chat API), free models only.

Per https://openrouter.ai/docs: POST /api/v1/chat/completions with
`Authorization: Bearer <key>`; text at choices[0].message.content; errors
as {"error": {"code", "message"}}, sometimes inside an HTTP 200. Free model
ids end in ":free" (or the "openrouter/free" router); GET /api/v1/key
returns key details without running a model.

Free-only is enforced three ways: the configured model must be free
(validated in Settings), requests name exactly one model and never a
fallback list, and a response reporting a non-zero cost is rejected.
"""

import logging
from typing import Any

import httpx

from app.ai.provider import AIProviderInterface, AIProviderResponse, Prompt
from app.core.config import Settings
from app.core.exceptions import AIProviderException

logger = logging.getLogger(__name__)

PROVIDER_NAME = "openrouter"
# Fixed, not configurable: a user's key is only ever sent to this host.
BASE_URL = "https://openrouter.ai/api/v1"
_APP_TITLE = "AVAP"

_STATUS_MESSAGES = {
    401: "OpenRouter rejected the API key. Check the key on your Profile page.",
    402: "OpenRouter reports insufficient credits for this key.",
    403: "OpenRouter refused the request (permissions or moderation).",
    404: "The configured free OpenRouter model is not available any more.",
    408: "OpenRouter timed out. Try again shortly.",
    429: "OpenRouter's free-model rate limit was reached. Try again later.",
    502: "The free model is down or returned an invalid response.",
    503: (
        "No free OpenRouter provider is available for this model. Check the "
        "model, or your OpenRouter privacy settings for free models."
    ),
}


class OpenRouterProvider(AIProviderInterface):
    """Calls one free OpenRouter model with the requesting user's own key."""

    def __init__(self, settings: Settings, api_key: str):
        self._api_key = api_key
        self._model = settings.openrouter_model
        self._data_collection = settings.openrouter_data_collection
        self._timeout = settings.ai_request_timeout_seconds
        self._max_tokens = settings.ai_max_tokens

    def generate(self, prompt: Prompt) -> AIProviderResponse:
        payload = self._post(
            "/chat/completions",
            {
                # Exactly one model and no "models" fallback list, so
                # OpenRouter cannot route to a paid model.
                "model": self._model,
                "messages": [
                    {"role": "system", "content": prompt.system},
                    {"role": "user", "content": prompt.user},
                ],
                "max_tokens": self._max_tokens,
                "provider": {"data_collection": self._data_collection},
            },
        )
        _reject_paid_usage(payload)
        content = _content(payload)
        if not content.strip():
            raise AIProviderException("AI provider returned an empty response.")
        return AIProviderResponse(
            content=content, provider=PROVIDER_NAME, model=self._model
        )

    def check_key(self) -> None:
        """Validate the key via GET /key, which runs no model."""
        self._request("GET", "/key", None)

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", path, body)

    def _request(
        self, method: str, path: str, body: dict[str, Any] | None
    ) -> dict[str, Any]:
        try:
            response = httpx.request(
                method,
                f"{BASE_URL}{path}",
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                    "X-OpenRouter-Title": _APP_TITLE,
                },
                json=body,
                timeout=self._timeout,
                follow_redirects=False,
            )
        except httpx.TimeoutException as exc:
            self._log_failure("timeout")
            raise AIProviderException("AI provider request timed out.") from exc
        except httpx.RequestError as exc:
            self._log_failure("request_error")
            raise AIProviderException("Failed to reach the AI provider.") from exc

        if response.status_code >= 400:
            self._log_failure("http_status", status_code=response.status_code)
            raise AIProviderException(_status_message(response.status_code))
        try:
            payload = response.json()
        except ValueError as exc:
            raise AIProviderException(
                "AI provider returned a malformed response."
            ) from exc
        if not isinstance(payload, dict):
            raise AIProviderException("AI provider returned a malformed response.")
        _raise_embedded_error(payload)
        return payload

    def _log_failure(self, reason: str, status_code: int | None = None) -> None:
        logger.warning(
            "OpenRouter request failed",
            extra={
                "context": {
                    "provider": PROVIDER_NAME,
                    "model": self._model,
                    "reason": reason,
                    "status_code": status_code,
                }
            },
        )


def _status_message(status_code: int) -> str:
    return _STATUS_MESSAGES.get(
        status_code, f"AI provider returned an error status: {status_code}."
    )


def _raise_embedded_error(payload: dict[str, Any]) -> None:
    """OpenRouter can report a generation error inside an HTTP 200."""
    error = payload.get("error")
    if error is None:
        choices = payload.get("choices")
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            error = choices[0].get("error")
    if error is None:
        return
    code = error.get("code") if isinstance(error, dict) else None
    raise AIProviderException(
        _status_message(code) if isinstance(code, int) else "AI provider error."
    )


def _reject_paid_usage(payload: dict[str, Any]) -> None:
    """Last line of the free-only guarantee: never accept a billed response."""
    usage = payload.get("usage")
    cost = usage.get("cost") if isinstance(usage, dict) else None
    if isinstance(cost, int | float) and cost > 0:
        logger.error(
            "OpenRouter reported a non-zero cost for a free-only request",
            extra={"context": {"provider": PROVIDER_NAME, "cost": cost}},
        )
        raise AIProviderException(
            "OpenRouter charged for this request; AVAP only uses free models."
        )


def _content(payload: dict[str, Any]) -> str:
    try:
        content = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise AIProviderException("AI provider returned a malformed response.") from exc
    return content if isinstance(content, str) else ""
