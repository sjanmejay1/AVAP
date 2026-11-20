"""Provider-neutral contract every AI provider implementation must satisfy.

Business logic (the AI Service, prompt builder, response validator) depends
only on the types defined here — never on a concrete provider's request or
response structures.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass

from app.core.config import Settings


@dataclass(frozen=True)
class Prompt:
    """A provider-neutral prompt, separated into its trust-boundary parts."""

    system: str
    user: str


@dataclass(frozen=True)
class AIProviderResponse:
    """Provider-neutral raw textual result returned by an AI provider call."""

    content: str
    provider: str
    model: str


class AIProviderInterface(ABC):
    """Common interface implemented by every AI provider adapter.

    Every implementation is constructed with the application `Settings`
    (model, timeouts) and the requesting user's own API key, so
    `AIManager` can construct any registered provider uniformly by type.
    There is no server-wide key.
    """

    @abstractmethod
    def __init__(self, settings: Settings, api_key: str) -> None: ...

    @abstractmethod
    def generate(self, prompt: Prompt) -> AIProviderResponse:
        """Execute a single generation request and return its raw text content.

        Implementations must translate all transport-level failures (network
        errors, timeouts, non-success responses, malformed or empty output)
        into AVAP AI exceptions. They must never raise raw HTTP client
        exceptions to callers.
        """
        raise NotImplementedError

    @abstractmethod
    def check_key(self) -> None:
        """Make the cheapest possible authenticated call to prove the key
        works. Raises an AVAP AI exception if it does not."""
        raise NotImplementedError
