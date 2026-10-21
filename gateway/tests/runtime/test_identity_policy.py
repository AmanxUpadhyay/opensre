"""Gateway defaults cannot restore identities after a stored policy takes ownership."""

from __future__ import annotations

from gateway.core.middleware.identity_policy import load_identity_policy
from integrations.store import upsert_instance


def test_startup_identities_apply_only_without_a_stored_policy() -> None:
    _, policy = load_identity_policy("telegram", fallback_allowed_user_ids=["42"])
    assert policy.inbound_enabled
    assert policy.allowed_user_id_set() == {"42"}

    upsert_instance("telegram", {"name": "default", "credentials": {"identity_policy": {}}})

    _, policy = load_identity_policy("telegram", fallback_allowed_user_ids=["42"])
    assert not policy.inbound_enabled
    assert policy.allowed_user_id_set() == set()
