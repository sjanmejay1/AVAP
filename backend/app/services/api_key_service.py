"""Per-user AI provider keys: encrypted at rest, write-only over the API."""

import uuid
from collections.abc import Sequence

from sqlalchemy.orm import Session

from app.ai.manager import AIManager
from app.audit.context import AuditContext
from app.auth.key_cipher import KeyCipher, KeyDecryptionError
from app.core.enums import (
    AIKeyProvider,
    AuditEventCategory,
    AuditEventType,
    AuditOutcome,
    AuditResourceType,
)
from app.core.exceptions import AIKeyRequiredException, NotFoundException
from app.models.user_api_key import UserApiKey
from app.repositories.user_api_key_repository import UserApiKeyRepository
from app.services.audit_service import AuditService


class ApiKeyService:
    """Saves, lists, deletes and (internally) decrypts provider keys.

    Audit events record only the provider, never the key or its suffix.
    """

    def __init__(
        self,
        session: Session,
        keys: UserApiKeyRepository,
        audit_service: AuditService,
        cipher: KeyCipher,
    ):
        self.session = session
        self.keys = keys
        self.audit_service = audit_service
        self.cipher = cipher

    def save_key(
        self,
        user_id: uuid.UUID,
        provider: AIKeyProvider,
        api_key: str,
        context: AuditContext,
    ) -> UserApiKey:
        """Create or replace the user's key for one provider."""
        stored = self.keys.get(user_id, provider.value) or UserApiKey(
            user_id=user_id, provider=provider.value
        )
        stored.encrypted_key = self.cipher.encrypt(api_key)
        stored.last4 = api_key[-4:]
        self.keys.save(stored)
        self._audit(AuditEventType.API_KEY_SAVED, provider, user_id, context)
        self.session.commit()
        self.session.refresh(stored)
        return stored

    def list_keys(self, user_id: uuid.UUID) -> Sequence[UserApiKey]:
        return self.keys.list_for_user(user_id)

    def delete_key(
        self, user_id: uuid.UUID, provider: AIKeyProvider, context: AuditContext
    ) -> None:
        stored = self.keys.get(user_id, provider.value)
        if stored is None:
            raise NotFoundException(f"No {provider.value} key is saved.")
        self.keys.delete(stored)
        self._audit(AuditEventType.API_KEY_DELETED, provider, user_id, context)
        self.session.commit()

    def get_decrypted_key(self, user_id: uuid.UUID, provider: AIKeyProvider) -> str:
        """Return the plaintext key for server-side use only.

        Raises:
            AIKeyRequiredException: if no usable key is saved. A key that no
                longer decrypts (APP_ENCRYPTION_KEY changed) counts as missing.
        """
        stored = self.keys.get(user_id, provider.value)
        if stored is None:
            raise AIKeyRequiredException(provider.value)
        try:
            return self.cipher.decrypt(stored.encrypted_key)
        except KeyDecryptionError as exc:
            raise AIKeyRequiredException(provider.value) from exc

    def test_key(self, user_id: uuid.UUID, provider: AIKeyProvider) -> None:
        """Prove the saved key works with one minimal provider call.

        Raises:
            AIKeyRequiredException: if no key is saved.
            AIProviderException: with a user-safe reason if the call fails.
        """
        AIManager(api_key=self.get_decrypted_key(user_id, provider)).check_key()

    def find_decrypted_key(
        self, user_id: uuid.UUID, provider: AIKeyProvider
    ) -> str | None:
        """Like get_decrypted_key, but None instead of an exception when the
        user has no usable key (used where AI is optional, e.g. after a scan)."""
        try:
            return self.get_decrypted_key(user_id, provider)
        except AIKeyRequiredException:
            return None

    def _audit(
        self,
        event_type: AuditEventType,
        provider: AIKeyProvider,
        user_id: uuid.UUID,
        context: AuditContext,
    ) -> None:
        self.audit_service.append_event(
            event_type=event_type,
            category=AuditEventCategory.AUTH,
            outcome=AuditOutcome.SUCCESS,
            context=context,
            resource_type=AuditResourceType.API_KEY,
            resource_id=user_id,
            metadata={"provider": provider.value},
        )
