from __future__ import annotations

from gateway.transports.slack.processing.security import (
    enforce_inbound_slack_message_security,
)

_SECURITY = "gateway.transports.slack.processing.security"


def test_allowlisted_user_is_authorized() -> None:
    decision = enforce_inbound_slack_message_security(
        user_id="U111",
        channel_id="C222",
        text="check disk usage",
        env_allowed_user_ids=["U111", "U999"],
    )
    assert decision.allowed is True


def test_unlisted_user_is_denied() -> None:
    decision = enforce_inbound_slack_message_security(
        user_id="U666",
        channel_id="C222",
        text="check disk usage",
        env_allowed_user_ids=["U111"],
    )
    assert decision.allowed is False
    # Denial reasons stay in the audit log; the channel reply carries nothing.
    assert decision.reply_text == ""


def test_empty_allowlist_denied_without_open_flag() -> None:
    decision = enforce_inbound_slack_message_security(
        user_id="Uanybody",
        channel_id="C222",
        text="hello",
        env_allowed_user_ids=[],
        allow_open_workspace=False,
    )
    assert decision.allowed is False
    assert decision.reply_text == ""


def test_empty_allowlist_open_when_explicitly_enabled() -> None:
    decision = enforce_inbound_slack_message_security(
        user_id="Uanybody",
        channel_id="C222",
        text="hello",
        env_allowed_user_ids=[],
        allow_open_workspace=True,
    )
    assert decision.allowed is True


def test_help_is_not_agent_turn() -> None:
    decision = enforce_inbound_slack_message_security(
        user_id="U111",
        channel_id="C222",
        text="/help",
        env_allowed_user_ids=["U111"],
    )
    assert decision.allowed is False
    assert "OpenSRE Slack gateway" in decision.reply_text


def test_unauthorized_user_cannot_rotate_session() -> None:
    decision = enforce_inbound_slack_message_security(
        user_id="U666",
        channel_id="C222",
        text="/new",
        env_allowed_user_ids=["U111"],
    )
    assert decision.allowed is False
    assert decision.reply_text != "__ROTATE_SESSION__"


def test_authorized_user_can_rotate_session() -> None:
    decision = enforce_inbound_slack_message_security(
        user_id="U111",
        channel_id="C222",
        text="/new",
        env_allowed_user_ids=["U111"],
    )
    assert decision.allowed is True
    assert decision.reply_text == "__ROTATE_SESSION__"
