"""Atomic messaging identity-policy updates on a single integration instance."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from integrations.messaging_security import MessagingIdentityPolicy
from integrations.store import (
    AmbiguousIntegrationInstance as AmbiguousMessagingIntegration,
)
from integrations.store import get_single_integration, update_single_instance_credentials


def _policy_from_credentials(
    credentials: dict[str, Any], default_policy: MessagingIdentityPolicy | None = None
) -> MessagingIdentityPolicy:
    raw_policy = credentials.get("identity_policy")
    if raw_policy is None:
        return (
            default_policy.model_copy(deep=True)
            if default_policy is not None
            else MessagingIdentityPolicy(inbound_enabled=True)
        )
    return MessagingIdentityPolicy.model_validate(raw_policy)


def load_identity_policy(platform: str) -> tuple[dict[str, Any] | None, MessagingIdentityPolicy]:
    """Load the sole active instance; an absent policy defaults to inbound enabled."""
    record = get_single_integration(platform)
    credentials = record.get("credentials", {}) if record is not None else {}
    return record, _policy_from_credentials(credentials)


def update_identity_policy[Result](
    platform: str,
    mutate: Callable[[MessagingIdentityPolicy], Result],
    *,
    default_policy: MessagingIdentityPolicy | None = None,
) -> Result:
    """Apply a mutation to the latest policy while holding the integration-store lock.

    A stored policy is authoritative, including empty allowlists and disabled inbound.
    ``default_policy`` only supplies startup settings when no policy is stored.
    """

    def _mutate(credentials: dict[str, Any]) -> Result:
        policy = _policy_from_credentials(credentials, default_policy)
        before = policy.model_dump(mode="json")
        result = mutate(policy)
        after = policy.model_dump(mode="json")
        if after != before:
            credentials["identity_policy"] = after
        return result

    return update_single_instance_credentials(platform, _mutate)


__all__ = ["AmbiguousMessagingIntegration", "load_identity_policy", "update_identity_policy"]
