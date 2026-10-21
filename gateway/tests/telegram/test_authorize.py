from __future__ import annotations

from unittest.mock import patch

import pytest

from gateway.transports.telegram.inbound_security import (
    enforce_inbound_telegram_message_security,
)
from integrations.messaging_security import MessagingIdentityPolicy

_SECURITY = "gateway.transports.telegram.inbound_security"


def test_help_is_not_agent_turn() -> None:
    decision = enforce_inbound_telegram_message_security(
        user_id="42",
        chat_id="42",
        text="/help",
        env_allowed_user_ids=["42"],
    )
    assert decision.allowed is False
    assert "OpenSRE Telegram gateway" in decision.reply_text


def test_unauthorized_user_gets_reason() -> None:
    decision = enforce_inbound_telegram_message_security(
        user_id="99",
        chat_id="99",
        text="hello",
        env_allowed_user_ids=["42"],
    )
    assert decision.allowed is False
    assert decision.reply_text


def test_unauthorized_user_cannot_rotate_session() -> None:
    decision = enforce_inbound_telegram_message_security(
        user_id="99",
        chat_id="99",
        text="/new",
        env_allowed_user_ids=["42"],
    )
    assert decision.allowed is False
    assert decision.reply_text
    assert decision.reply_text != "__ROTATE_SESSION__"


def test_authorized_user_can_rotate_session() -> None:
    decision = enforce_inbound_telegram_message_security(
        user_id="42",
        chat_id="42",
        text="/new",
        env_allowed_user_ids=["42"],
    )
    assert decision.allowed is True
    assert decision.reply_text == "__ROTATE_SESSION__"


def _connected_record(chat_id: str, **policy: object) -> dict[str, object]:
    credentials: dict[str, object] = {"bot_token": "t", "default_chat_id": chat_id}
    if policy:
        credentials["identity_policy"] = MessagingIdentityPolicy(
            inbound_enabled=True, **policy
        ).model_dump(mode="json")
    return {"id": "r1", "credentials": credentials}


@pytest.mark.parametrize(
    ("chat_id", "user_id", "allowed"),
    [
        ("123456789", "123456789", True),  # connecting a private chat authorizes it
        ("123456789", "99", False),  # anyone else still needs to be allowed
        ("-1001234567890", "1001234567890", False),  # group/channel IDs never name a user
    ],
)
def test_connected_private_chat_is_authorized_without_pairing(
    chat_id: str, user_id: str, allowed: bool
) -> None:
    with (
        patch(
            "integrations.messaging_policy_store.get_single_integration",
            return_value=_connected_record(chat_id),
        ),
    ):
        decision = enforce_inbound_telegram_message_security(
            user_id=user_id, chat_id=user_id, text="hello", env_allowed_user_ids=[]
        )
    assert decision.allowed is allowed


def test_connected_chat_respects_allowed_chat_ids() -> None:
    record = _connected_record("123456789", allowed_chat_ids=["-100"])
    with (
        patch("integrations.messaging_policy_store.get_single_integration", return_value=record),
    ):
        decision = enforce_inbound_telegram_message_security(
            user_id="123456789", chat_id="123456789", text="hello", env_allowed_user_ids=[]
        )
    assert decision.allowed is False


def test_connected_chat_does_not_override_a_persisted_revocation() -> None:
    from integrations.store import upsert_instance

    upsert_instance(
        "telegram",
        {
            "name": "default",
            "credentials": {
                "default_chat_id": "42",
                "identity_policy": {"inbound_enabled": True, "allowed_user_ids": []},
            },
        },
    )

    decision = enforce_inbound_telegram_message_security(
        user_id="42", chat_id="42", text="hello", env_allowed_user_ids=["42"]
    )

    assert not decision.allowed
