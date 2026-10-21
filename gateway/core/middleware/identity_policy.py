"""Resolve live inbound identities and atomically authorize pairing attempts."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from config.scope_context import bound_storage_scope
from integrations.messaging_policy_store import load_identity_policy as load_stored_identity_policy
from integrations.messaging_policy_store import update_identity_policy
from integrations.messaging_security import (
    MessagingIdentityPolicy,
    authorize_inbound_message,
    complete_pairing,
)


def has_stored_identity_policy(record: dict[str, Any] | None) -> bool:
    """An explicit policy, including an empty one, owns authorization over startup defaults."""
    return record is not None and isinstance(
        (record.get("credentials") or {}).get("identity_policy"), dict
    )


def load_identity_policy(
    platform: str, *, fallback_allowed_user_ids: Sequence[str] = ()
) -> tuple[dict[str, Any] | None, MessagingIdentityPolicy]:
    """Read the gateway's config policy, using startup identities only without one.

    The bot and CLI use the unbound configuration store. A turn's organization
    scope selects its tool credentials, not a different inbound bot policy.
    Explicit integration-store overrides still apply in the host context.
    """
    with bound_storage_scope(None):
        record, policy = load_stored_identity_policy(platform)
    if not has_stored_identity_policy(record):
        policy.allowed_user_ids = list(fallback_allowed_user_ids)
        policy._invalidate_allowed_user_id_cache()
    return record, policy


def authorize_pairing(
    platform: str,
    *,
    user_id: str,
    chat_id: str,
    text: str,
    fallback_allowed_user_ids: Sequence[str],
) -> tuple[bool, str]:
    """Validate and consume a pairing code against the latest policy in one transaction."""

    def pair(policy: MessagingIdentityPolicy) -> tuple[bool, str]:
        result = authorize_inbound_message(
            policy=policy, user_id=user_id, chat_id=chat_id, message_text=text
        )
        if not result:
            return (
                False,
                "Pairing is unavailable. Ask the operator to check inbound access and generate a pairing code.",
            )
        if not result.is_pairing_attempt:
            return True, result.reason
        return complete_pairing(
            policy=policy, user_id=user_id, code=text.strip().split(maxsplit=1)[1]
        )

    with bound_storage_scope(None):
        return update_identity_policy(
            platform,
            pair,
            default_policy=MessagingIdentityPolicy(
                inbound_enabled=True, allowed_user_ids=list(fallback_allowed_user_ids)
            ),
        )


def is_user_authorized(
    platform: str,
    *,
    user_id: str,
    chat_id: str,
    fallback_allowed_user_ids: Sequence[str],
    allow_open: bool = False,
) -> bool:
    """Check live policy for approval clicks without reusing a startup allowlist."""
    _, policy = load_identity_policy(platform, fallback_allowed_user_ids=fallback_allowed_user_ids)
    if not policy.allowed_user_ids:
        if not allow_open:
            return False
        policy.require_dm_pairing = False
    return bool(authorize_inbound_message(policy=policy, user_id=user_id, chat_id=chat_id))


__all__ = [
    "authorize_pairing",
    "has_stored_identity_policy",
    "is_user_authorized",
    "load_identity_policy",
]
