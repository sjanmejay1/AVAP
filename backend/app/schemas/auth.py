import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.enums import AIKeyProvider

MIN_PASSWORD_LENGTH = 12
# Argon2 handles long input, but an upper bound stops multi-megabyte
# "passwords" from being hashed on every request.
MAX_PASSWORD_LENGTH = 128


def _normalize_email(value: str) -> str:
    email = value.strip().lower()
    local, sep, domain = email.partition("@")
    if not sep or not local or "." not in domain or " " in email:
        raise ValueError("Enter a valid email address.")
    return email


class CredentialsRequest(BaseModel):
    """Email and password, used for both registration and login."""

    email: str = Field(..., max_length=254)
    password: str = Field(
        ..., min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH
    )

    @field_validator("email")
    @classmethod
    def _email(cls, value: str) -> str:
        return _normalize_email(value)


class LoginRequest(BaseModel):
    """Login accepts any password length up to the cap, so the minimum
    introduced later never locks out an existing account."""

    email: str = Field(..., max_length=254)
    password: str = Field(..., min_length=1, max_length=MAX_PASSWORD_LENGTH)

    @field_validator("email")
    @classmethod
    def _email(cls, value: str) -> str:
        return _normalize_email(value)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=MAX_PASSWORD_LENGTH)
    new_password: str = Field(
        ..., min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH
    )


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 -- OAuth2 token type label
    expires_in: int = Field(description="Access token lifetime in seconds.")
    user: UserResponse


class SaveApiKeyRequest(BaseModel):
    api_key: str = Field(..., min_length=8, max_length=512)

    @field_validator("api_key")
    @classmethod
    def _no_whitespace(cls, value: str) -> str:
        key = value.strip()
        if any(ch.isspace() for ch in key):
            raise ValueError("API keys cannot contain spaces.")
        return key


class ApiKeyResponse(BaseModel):
    provider: AIKeyProvider
    last4: str
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ApiKeyListResponse(BaseModel):
    keys: list[ApiKeyResponse]


class ApiKeyTestResponse(BaseModel):
    valid: bool
    message: str
