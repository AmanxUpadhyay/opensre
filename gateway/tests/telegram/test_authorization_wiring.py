"""Polled messages use live policy even when the gateway started with an allowed user."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock

import pytest

from gateway.core.middleware.active_turns import ActiveTurnRegistry
from gateway.core.middleware.approvals import ApprovalBroker
from gateway.transports.telegram.inbound_handler import handle_polled_inbound_telegram_message
from gateway.transports.telegram.settings import GatewaySettings, TelegramInboundMessage
from integrations.messaging_policy_store import update_identity_policy
from integrations.messaging_security import MessagingIdentityPolicy


@pytest.mark.parametrize("text", ["hello", "/new"])
def test_revocation_blocks_turns_and_session_rotation_without_restart(
    monkeypatch: pytest.MonkeyPatch, text: str
) -> None:
    monkeypatch.setenv("ORGANIZATION_ID", "org_policy")
    settings = GatewaySettings(bot_token="test", allowed_user_ids=["42"])

    def revoke(policy: MessagingIdentityPolicy) -> None:
        policy.allowed_user_ids = []

    update_identity_policy(
        "telegram",
        revoke,
        default_policy=MessagingIdentityPolicy(inbound_enabled=True, allowed_user_ids=["42"]),
    )
    resolver = MagicMock()
    callback = MagicMock()
    client = MagicMock()
    with ThreadPoolExecutor(max_workers=1) as executor:
        asyncio.run(
            handle_polled_inbound_telegram_message(
                TelegramInboundMessage(
                    update_id=1, user_id="42", chat_id="42", message_id="1", text=text
                ),
                client=client,
                session_resolver=resolver,
                settings=settings,
                executor=executor,
                chat_locks={},
                turn_semaphore=asyncio.Semaphore(1),
                approvals=ApprovalBroker(),
                active_cancels=ActiveTurnRegistry(),
                handle_callback_to_gateway_agent=callback,
            )
        )

    callback.assert_not_called()
    resolver.resolve.assert_not_called()
    resolver.rotate.assert_not_called()
