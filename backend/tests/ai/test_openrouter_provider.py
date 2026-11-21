"""OpenRouter adapter: free-only request shape, key handling, error mapping.
No network: httpx.request is patched."""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from app.ai.provider import Prompt
from app.ai.providers.openrouter import BASE_URL, OpenRouterProvider
from app.core.config import Settings
from app.core.exceptions import AIProviderException

KEY = "sk-or-v1-test-secret-key-value"
REQUEST = "app.ai.providers.openrouter.httpx.request"


def _provider(**overrides) -> OpenRouterProvider:
    settings = Settings(
        _env_file=None,
        openrouter_model="org/model:free",
        ai_max_tokens=321,
        **overrides,
    )
    return OpenRouterProvider(settings, KEY)


def _response(status: int, body: object) -> MagicMock:
    response = MagicMock(status_code=status)
    response.json.return_value = body
    return response


def _ok(content: str = '{"findings": []}', cost: float | None = 0) -> MagicMock:
    body: dict = {"choices": [{"message": {"content": content}}]}
    if cost is not None:
        body["usage"] = {"cost": cost}
    return _response(200, body)


def test_generate_sends_one_free_model_with_the_user_key():
    with patch(REQUEST, return_value=_ok()) as request:
        result = _provider().generate(Prompt(system="sys", user="usr"))

    method, url = request.call_args.args
    kwargs = request.call_args.kwargs
    body = kwargs["json"]
    assert (method, url) == ("POST", f"{BASE_URL}/chat/completions")
    assert url.startswith("https://openrouter.ai/")
    assert kwargs["headers"]["Authorization"] == f"Bearer {KEY}"
    assert body["model"] == "org/model:free"
    assert "models" not in body  # no fallback list that could reach a paid model
    assert body["max_tokens"] == 321
    assert body["provider"] == {"data_collection": "allow"}
    assert body["messages"] == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "usr"},
    ]
    assert kwargs["follow_redirects"] is False
    assert result.content == '{"findings": []}'
    assert result.provider == "openrouter"


def test_data_collection_policy_is_passed_through():
    with patch(REQUEST, return_value=_ok()) as request:
        _provider(openrouter_data_collection="deny").generate(
            Prompt(system="s", user="u")
        )
    assert request.call_args.kwargs["json"]["provider"] == {"data_collection": "deny"}


def test_a_billed_response_is_rejected():
    with (
        patch(REQUEST, return_value=_ok(cost=0.0012)),
        pytest.raises(AIProviderException, match="only uses free models"),
    ):
        _provider().generate(Prompt(system="s", user="u"))


def test_check_key_uses_the_key_endpoint_and_runs_no_model():
    with patch(REQUEST, return_value=_response(200, {"data": {}})) as request:
        _provider().check_key()
    assert request.call_args.args == ("GET", f"{BASE_URL}/key")
    assert request.call_args.kwargs["json"] is None


@pytest.mark.parametrize(
    ("status", "fragment"),
    [
        (401, "rejected the API key"),
        (402, "insufficient credits"),
        (404, "not available"),
        (429, "rate limit"),
        (503, "No free OpenRouter provider"),
        (500, "error status: 500"),
    ],
)
def test_error_statuses_map_to_safe_messages(status, fragment):
    with (
        patch(REQUEST, return_value=_response(status, {"error": {"message": KEY}})),
        pytest.raises(AIProviderException) as exc,
    ):
        _provider().generate(Prompt(system="s", user="u"))
    assert fragment in exc.value.message
    assert KEY not in exc.value.message


@pytest.mark.parametrize(
    "body",
    [
        {"error": {"code": 429, "message": "Rate limit exceeded"}},
        {"choices": [{"error": {"code": 502, "message": "down"}}]},
    ],
)
def test_errors_inside_http_200_are_raised(body):
    with (
        patch(REQUEST, return_value=_response(200, body)),
        pytest.raises(AIProviderException),
    ):
        _provider().generate(Prompt(system="s", user="u"))


@pytest.mark.parametrize("error", [httpx.ConnectTimeout("t"), httpx.ConnectError("c")])
def test_transport_errors_become_provider_errors(error):
    with patch(REQUEST, side_effect=error), pytest.raises(AIProviderException):
        _provider().generate(Prompt(system="s", user="u"))


@pytest.mark.parametrize("body", [{}, {"choices": []}, {"choices": [{"message": {}}]}])
def test_malformed_responses_are_rejected(body):
    with (
        patch(REQUEST, return_value=_response(200, body)),
        pytest.raises(AIProviderException),
    ):
        _provider().generate(Prompt(system="s", user="u"))


def test_non_json_and_empty_content_are_rejected():
    bad = _response(200, None)
    bad.json.side_effect = ValueError("not json")
    with patch(REQUEST, return_value=bad), pytest.raises(AIProviderException):
        _provider().generate(Prompt(system="s", user="u"))
    with patch(REQUEST, return_value=_ok("   ")), pytest.raises(AIProviderException):
        _provider().generate(Prompt(system="s", user="u"))
