"""Hugging Face adapter: request shape, key handling and error mapping.
No network: httpx.post is patched."""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from app.ai.provider import Prompt
from app.ai.providers.huggingface import BASE_URL, HuggingFaceProvider
from app.core.config import Settings
from app.core.exceptions import AIProviderException

KEY = "hf_test_secret_key_value"


def _provider() -> HuggingFaceProvider:
    settings = Settings(
        _env_file=None, huggingface_model="org/model:cheapest", ai_max_tokens=321
    )
    return HuggingFaceProvider(settings, KEY)


def _response(status: int, body: object) -> MagicMock:
    response = MagicMock(status_code=status)
    response.json.return_value = body
    return response


def _ok(content: str = '{"findings": []}') -> MagicMock:
    return _response(200, {"choices": [{"message": {"content": content}}]})


def test_generate_calls_the_router_with_the_user_key():
    with patch("app.ai.providers.huggingface.httpx.post", return_value=_ok()) as post:
        result = _provider().generate(Prompt(system="sys", user="usr"))

    url = post.call_args.args[0]
    kwargs = post.call_args.kwargs
    assert url == f"{BASE_URL}/chat/completions"
    assert url.startswith("https://router.huggingface.co/")
    assert kwargs["headers"]["Authorization"] == f"Bearer {KEY}"
    assert kwargs["json"]["model"] == "org/model:cheapest"
    assert kwargs["json"]["max_tokens"] == 321
    assert kwargs["json"]["messages"] == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "usr"},
    ]
    assert kwargs["follow_redirects"] is False
    assert result.content == '{"findings": []}'
    assert result.provider == "huggingface"


def test_check_key_makes_a_one_token_call():
    with patch(
        "app.ai.providers.huggingface.httpx.post", return_value=_ok("x")
    ) as post:
        _provider().check_key()
    assert post.call_args.kwargs["json"]["max_tokens"] == 1


@pytest.mark.parametrize(
    ("status", "fragment"),
    [
        (401, "rejected the API key"),
        (402, "no inference credits"),
        (403, "not allowed"),
        (429, "rate limit"),
        (500, "error status: 500"),
    ],
)
def test_error_statuses_map_to_safe_messages(status, fragment):
    with (
        patch(
            "app.ai.providers.huggingface.httpx.post",
            return_value=_response(status, {"error": KEY}),
        ),
        pytest.raises(AIProviderException) as exc,
    ):
        _provider().generate(Prompt(system="s", user="u"))
    assert fragment in exc.value.message
    assert KEY not in exc.value.message


@pytest.mark.parametrize("error", [httpx.ConnectTimeout("t"), httpx.ConnectError("c")])
def test_transport_errors_become_provider_errors(error):
    with (
        patch("app.ai.providers.huggingface.httpx.post", side_effect=error),
        pytest.raises(AIProviderException),
    ):
        _provider().generate(Prompt(system="s", user="u"))


@pytest.mark.parametrize(
    "body", [{}, {"choices": []}, {"choices": [{"message": {}}]}, "not json"]
)
def test_malformed_responses_are_rejected(body):
    response = _response(200, body)
    if body == "not json":
        response.json.side_effect = ValueError("bad json")
    with (
        patch("app.ai.providers.huggingface.httpx.post", return_value=response),
        pytest.raises(AIProviderException),
    ):
        _provider().generate(Prompt(system="s", user="u"))


def test_empty_content_is_rejected():
    with (
        patch("app.ai.providers.huggingface.httpx.post", return_value=_ok("   ")),
        pytest.raises(AIProviderException),
    ):
        _provider().generate(Prompt(system="s", user="u"))
