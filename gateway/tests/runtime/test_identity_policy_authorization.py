"""Stored revocations and pairing restrictions apply at every transport ingress."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import pytest

from gateway.transports.buzz.inbound_security import enforce_inbound_buzz_message_security
from gateway.transports.discord.security import enforce_inbound_discord_message_security
from gateway.transports.slack.processing.security import enforce_inbound_slack_message_security
from gateway.transports.telegram.inbound_security import enforce_inbound_telegram_message_security
from integrations.messaging_security import MessagingIdentityPolicy, hash_pairing_code
from integrations.store import get_integration, upsert_instance

_INGRESS: dict[str, tuple[Callable[..., Any], str, str, str]] = {
    "slack": (
        enforce_inbound_slack_message_security,
        "user_id",
        "channel_id",
        "env_allowed_user_ids",
    ),
    "discord": (
        enforce_inbound_discord_message_security,
        "user_id",
        "channel_id",
        "env_allowed_user_ids",
    ),
    "telegram": (
        enforce_inbound_telegram_message_security,
        "user_id",
        "chat_id",
        "env_allowed_user_ids",
    ),
    "buzz": (enforce_inbound_buzz_message_security, "pubkey", "channel_id", "env_allowed_pubkeys"),
}


def _ingress(platform: str, *, text: str = "hello", **kwargs: Any) -> Any:
    enforce, user_key, chat_key, fallback_key = _INGRESS[platform]
    return enforce(**{user_key: "42", chat_key: "42", fallback_key: ["42"], "text": text, **kwargs})


def _store_policy(platform: str, policy: MessagingIdentityPolicy) -> None:
    upsert_instance(
        platform,
        {"name": "default", "credentials": {"identity_policy": policy.model_dump(mode="json")}},
    )


@pytest.mark.parametrize("platform", _INGRESS)
def test_revoked_last_user_is_not_restored_from_startup_allowlist(platform: str) -> None:
    _store_policy(platform, MessagingIdentityPolicy(inbound_enabled=True, allowed_user_ids=["42"]))
    assert _ingress(platform).allowed

    _store_policy(platform, MessagingIdentityPolicy(inbound_enabled=True))

    assert not _ingress(platform).allowed


@pytest.mark.parametrize("platform", _INGRESS)
@pytest.mark.parametrize("restriction", ["disabled", "other_chat"])
def test_pairing_cannot_bypass_policy_restrictions(platform: str, restriction: str) -> None:
    policy = MessagingIdentityPolicy(
        inbound_enabled=restriction != "disabled",
        allowed_chat_ids=["other"] if restriction == "other_chat" else [],
        pairing_secret_hash=hash_pairing_code("ABC123"),
        pairing_created_at=time.time(),
    )
    _store_policy(platform, policy)

    decision = _ingress(platform, text="/pair ABC123")

    assert "successful" not in decision.reply_text.lower()
    record = get_integration(platform)
    assert record is not None
    assert record["credentials"]["identity_policy"] == policy.model_dump(mode="json")


@pytest.mark.parametrize("platform", ["slack", "discord"])
@pytest.mark.parametrize("restriction", ["disabled", "other_chat"])
def test_open_mode_still_enforces_policy_restrictions(platform: str, restriction: str) -> None:
    _store_policy(
        platform,
        MessagingIdentityPolicy(
            inbound_enabled=restriction != "disabled",
            allowed_chat_ids=["other"] if restriction == "other_chat" else [],
        ),
    )
    options = (
        {"allow_open_workspace": True}
        if platform == "slack"
        else {"allow_open_guild": True, "is_guild_message": True}
    )
    assert not _ingress(platform, env_allowed_user_ids=[], **options).allowed


@pytest.mark.parametrize("platform", _INGRESS)
def test_pairing_rechecks_rotated_code_and_revocation_after_initial_load(
    platform: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    import importlib

    from gateway.core.middleware.identity_policy import load_identity_policy

    policy = MessagingIdentityPolicy(
        inbound_enabled=True,
        allowed_user_ids=["revoked"],
        pairing_secret_hash=hash_pairing_code("OLD123"),
        pairing_created_at=time.time(),
    )
    _store_policy(platform, policy)
    rotated_hash = hash_pairing_code("NEW123")

    def load_then_rotate(*args: Any, **kwargs: Any) -> Any:
        snapshot = load_identity_policy(*args, **kwargs)
        policy.allowed_user_ids = []
        policy.pairing_secret_hash = rotated_hash
        _store_policy(platform, policy)
        return snapshot

    transport = importlib.import_module(_INGRESS[platform][0].__module__)
    monkeypatch.setattr(transport, "load_identity_policy", load_then_rotate)

    decision = _ingress(platform, text="/pair OLD123")

    assert "Invalid pairing code" in decision.reply_text
    record = get_integration(platform)
    assert record is not None
    stored = record["credentials"]["identity_policy"]
    assert stored["allowed_user_ids"] == []
    assert stored["pairing_secret_hash"] == rotated_hash
    assert stored["pairing_attempts"] == 1


@pytest.mark.parametrize("platform", _INGRESS)
def test_concurrent_pairing_consumes_one_time_code_only_once(
    platform: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    import importlib
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from gateway.core.middleware.identity_policy import load_identity_policy

    _store_policy(
        platform,
        MessagingIdentityPolicy(
            inbound_enabled=True,
            pairing_secret_hash=hash_pairing_code("ABC123"),
            pairing_created_at=time.time(),
        ),
    )
    loaded = threading.Barrier(2)

    def load_together(*args: Any, **kwargs: Any) -> Any:
        snapshot = load_identity_policy(*args, **kwargs)
        loaded.wait(timeout=5)
        return snapshot

    transport = importlib.import_module(_INGRESS[platform][0].__module__)
    monkeypatch.setattr(transport, "load_identity_policy", load_together)

    def pair(user_id: str) -> Any:
        return _ingress(platform, text="/pair ABC123", **{_INGRESS[platform][1]: user_id})

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(pair, ["42", "43"]))

    assert sum("successful" in result.reply_text for result in results) == 1
    record = get_integration(platform)
    assert record is not None
    stored = record["credentials"]["identity_policy"]
    assert len(stored["allowed_user_ids"]) == 1
    assert stored["pairing_secret_hash"] is None


@pytest.mark.parametrize("platform", _INGRESS)
def test_gateway_persists_failed_pairing_attempts(platform: str) -> None:
    _store_policy(
        platform,
        MessagingIdentityPolicy(
            inbound_enabled=True,
            pairing_secret_hash=hash_pairing_code("ABC123"),
            pairing_created_at=time.time(),
        ),
    )

    for _ in range(5):
        decision = _ingress(platform, text="/pair WRONG1")

    assert "Too many failed attempts" in decision.reply_text
    record = get_integration(platform)
    assert record is not None
    assert record["credentials"]["identity_policy"]["pairing_secret_hash"] is None
    assert record["credentials"]["identity_policy"]["allowed_user_ids"] == []
