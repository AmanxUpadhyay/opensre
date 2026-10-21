"""Messaging-policy updates are atomic and target only an unambiguous instance."""

from __future__ import annotations

import json
import multiprocessing
from multiprocessing.synchronize import Event
from pathlib import Path
from unittest.mock import patch

import pytest

from integrations.messaging_policy_store import load_identity_policy, update_identity_policy
from integrations.messaging_security import MessagingIdentityPolicy
from integrations.store import IntegrationStoreLockTimeout, upsert_instance


def _revoke_while_locked(store_file: str, entered: Event, release: Event) -> None:
    def revoke(policy: MessagingIdentityPolicy) -> None:
        policy.allowed_user_ids.remove("U001")
        policy.pairing_secret_hash = None
        policy.pairing_created_at = None
        policy.pairing_attempts = 0
        entered.set()
        assert release.wait(timeout=10), "Parent did not release the policy transaction"

    with patch("integrations.store.STORE_PATH", Path(store_file)):
        update_identity_policy("slack", revoke)


def test_policy_read_and_mutation_share_cross_process_write_lock(tmp_path: Path) -> None:
    store_file = tmp_path / "integrations.json"
    policy = MessagingIdentityPolicy(
        inbound_enabled=True,
        allowed_user_ids=["U001"],
        pairing_secret_hash="old-code-hash",
        pairing_created_at=100,
    )
    with patch("integrations.store.STORE_PATH", store_file):
        upsert_instance("slack", {"credentials": {"identity_policy": policy.model_dump()}})
        context = multiprocessing.get_context("spawn")
        entered, release = context.Event(), context.Event()
        process = context.Process(
            target=_revoke_while_locked,
            args=(str(store_file), entered, release),
        )
        process.start()
        try:
            assert entered.wait(timeout=10), "Revocation never entered its mutation callback"

            def allow(policy: MessagingIdentityPolicy) -> None:
                policy.allowed_user_ids.append("U002")

            with (
                patch("integrations.store._LOCK_TIMEOUT_SECONDS", 0.05),
                pytest.raises(IntegrationStoreLockTimeout),
            ):
                update_identity_policy("slack", allow)
        finally:
            release.set()
            process.join(timeout=10)
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
        assert process.exitcode == 0

        update_identity_policy("slack", allow)
        _, stored = load_identity_policy("slack")
        assert stored.allowed_user_ids == ["U002"]
        assert stored.pairing_secret_hash is None
        assert stored.pairing_created_at is None


@pytest.mark.parametrize("legacy", [False, True])
def test_policy_update_preserves_instance_identity_and_credentials(
    tmp_path: Path, legacy: bool
) -> None:
    store_file = tmp_path / "integrations.json"
    credentials = {"bot_token": "synthetic-token"}
    record = {
        "id": "slack-existing",
        "service": "slack",
        "status": "active",
        **(
            {"credentials": credentials}
            if legacy
            else {
                "instances": [
                    {"name": "ops", "tags": {"team": "infra"}, "credentials": credentials}
                ]
            }
        ),
    }
    other_record = {
        "id": "discord-existing",
        "service": "discord",
        "status": "active",
        "instances": [
            {
                "name": "ops",
                "credentials": {"identity_policy": {"allowed_user_ids": ["discord-user"]}},
            }
        ],
    }
    store_file.write_text(
        json.dumps(
            {
                "version": 1 if legacy else 2,
                "integrations": [record, other_record],
            }
        )
    )

    def allow(policy: MessagingIdentityPolicy) -> str:
        policy.allowed_user_ids.append("U001")
        return "added"

    with patch("integrations.store.STORE_PATH", store_file):
        assert update_identity_policy("slack", allow) == "added"
        record, stored = load_identity_policy("slack")
    assert record is not None
    assert record["id"] == "slack-existing"
    assert record["credentials"]["bot_token"] == "synthetic-token"
    assert record["instances"][0]["name"] == ("default" if legacy else "ops")
    assert record["instances"][0]["tags"] == ({} if legacy else {"team": "infra"})
    assert stored.allowed_user_ids == ["U001"]
    data = json.loads(store_file.read_text())
    assert data["version"] == 2
    assert data["integrations"][1] == other_record


def test_failed_policy_mutation_does_not_partially_write(tmp_path: Path) -> None:
    store_file = tmp_path / "integrations.json"
    with patch("integrations.store.STORE_PATH", store_file):
        upsert_instance("slack", {"credentials": {"bot_token": "synthetic-token"}})
        before = store_file.read_bytes()

        def fail(policy: MessagingIdentityPolicy) -> None:
            policy.allowed_user_ids.append("U001")
            raise ValueError("mutation failed")

        with pytest.raises(ValueError, match="mutation failed"):
            update_identity_policy("slack", fail)
    assert store_file.read_bytes() == before


def test_absent_policy_defaults_never_override_explicit_empty_policy(tmp_path: Path) -> None:
    store_file = tmp_path / "integrations.json"
    startup = MessagingIdentityPolicy(inbound_enabled=True, allowed_user_ids=["U001"])

    def effective_users(policy: MessagingIdentityPolicy) -> list[str]:
        return policy.allowed_user_ids

    with patch("integrations.store.STORE_PATH", store_file):
        assert update_identity_policy("slack", effective_users, default_policy=startup) == ["U001"]
        assert not store_file.exists(), "Read-only callbacks must not create a stored policy"
        upsert_instance("slack", {"credentials": {"identity_policy": {}}})
        assert update_identity_policy("slack", effective_users, default_policy=startup) == []
        _, policy = load_identity_policy("slack")
        assert not policy.inbound_enabled
