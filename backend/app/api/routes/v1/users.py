"""The logged-in user's profile: password change and AI provider keys."""

from fastapi import APIRouter, Depends, status

from app.api.dependencies.audit import get_audit_context
from app.api.dependencies.auth import (
    get_api_key_service,
    get_auth_service,
    get_current_user,
)
from app.api.responses.api_response import SuccessResponse
from app.audit.context import AuditContext
from app.core.enums import AIKeyProvider
from app.models.user import User
from app.schemas.auth import (
    ApiKeyListResponse,
    ApiKeyResponse,
    ChangePasswordRequest,
    SaveApiKeyRequest,
)
from app.services.api_key_service import ApiKeyService
from app.services.auth_service import AuthService

router = APIRouter()


@router.post(
    "/me/password",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Change password (signs out other sessions)",
)
def change_password(
    body: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    service: AuthService = Depends(get_auth_service),
    context: AuditContext = Depends(get_audit_context),
) -> None:
    service.change_password(
        current_user, body.current_password, body.new_password, context
    )


@router.get(
    "/me/api-keys",
    response_model=SuccessResponse[ApiKeyListResponse],
    summary="List saved provider keys (last 4 characters only)",
)
def list_api_keys(
    current_user: User = Depends(get_current_user),
    service: ApiKeyService = Depends(get_api_key_service),
) -> dict:
    stored = service.list_keys(current_user.id)
    keys = [ApiKeyResponse.model_validate(key) for key in stored]
    return {"data": ApiKeyListResponse(keys=keys)}


@router.put(
    "/me/api-keys/{provider}",
    response_model=SuccessResponse[ApiKeyResponse],
    summary="Save or replace a provider key",
)
def save_api_key(
    provider: AIKeyProvider,
    body: SaveApiKeyRequest,
    current_user: User = Depends(get_current_user),
    service: ApiKeyService = Depends(get_api_key_service),
    context: AuditContext = Depends(get_audit_context),
) -> dict:
    stored = service.save_key(current_user.id, provider, body.api_key, context)
    return {"data": ApiKeyResponse.model_validate(stored)}


@router.delete(
    "/me/api-keys/{provider}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a provider key",
)
def delete_api_key(
    provider: AIKeyProvider,
    current_user: User = Depends(get_current_user),
    service: ApiKeyService = Depends(get_api_key_service),
    context: AuditContext = Depends(get_audit_context),
) -> None:
    service.delete_key(current_user.id, provider, context)
