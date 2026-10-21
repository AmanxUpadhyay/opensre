"""Approval entrypoints must not preserve authority cached before revocation."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from gateway.core.middleware.approvals import APPROVE_ACTION_ID, ApprovalBroker
from gateway.transports.buzz.background import _resolve_if_approval_reply
from gateway.transports.buzz.pending_approvals import PendingApprovals
from gateway.transports.buzz.settings import BuzzInboundMessage
from gateway.transports.buzz.settings import GatewaySettings as BuzzSettings
from gateway.transports.discord.approvals import handle_component_interaction
from gateway.transports.slack.delivery.approvals import handle_block_actions_payload
from gateway.transports.telegram.approvals import handle_callback_query
from gateway.transports.telegram.settings import TelegramCallbackQuery
from integrations.messaging_security import MessagingIdentityPolicy
from integrations.store import upsert_instance


@pytest.mark.parametrize("platform", ["slack", "discord", "telegram", "buzz"])
@pytest.mark.parametrize("restriction", ["revoked", "disabled", "other_chat"])
def test_approval_rechecks_live_policy(platform: str, restriction: str) -> None:
    policy = MessagingIdentityPolicy(
        inbound_enabled=restriction != "disabled",
        allowed_user_ids=[] if restriction == "revoked" else ["42"],
        allowed_chat_ids=["other"] if restriction == "other_chat" else [],
    )
    upsert_instance(
        platform,
        {
            "name": "default",
            "credentials": {"identity_policy": policy.model_dump(mode="json")},
        },
    )
    broker = ApprovalBroker()
    approval_id = broker.create(platform=platform, chat_id="42")
    if platform == "slack":
        resolved = handle_block_actions_payload(
            {
                "type": "block_actions",
                "user": {"id": "42"},
                "channel": {"id": "42"},
                "actions": [{"action_id": APPROVE_ACTION_ID, "value": approval_id}],
            },
            broker=broker,
            allowed_user_ids=["42"],
            allow_open_workspace=False,
        )
        assert not resolved
    elif platform == "discord":
        interaction = SimpleNamespace(
            user=SimpleNamespace(id="42"),
            channel_id="42",
            data={"custom_id": f"{APPROVE_ACTION_ID}:{approval_id}"},
        )
        assert not handle_component_interaction(
            interaction,
            broker=broker,
            allowed_user_ids=["42"],  # type: ignore[arg-type]
        )
    elif platform == "telegram":
        assert not handle_callback_query(
            TelegramCallbackQuery(
                update_id=1,
                user_id="42",
                chat_id="42",
                callback_query_id="cb-1",
                data=f"{APPROVE_ACTION_ID}:{approval_id}",
            ),
            broker=broker,
            client=MagicMock(),
            allowed_user_ids=["42"],
        )
    else:
        pending = PendingApprovals()
        pending.register(
            "prompt-1", approval_id=approval_id, requester_pubkey="42", channel_id="42"
        )
        resources = SimpleNamespace(pending_approvals=pending, approvals=broker)
        assert _resolve_if_approval_reply(
            BuzzInboundMessage(
                event_id="reply-1",
                pubkey="42",
                channel_id="42",
                content="approve",
                created_at=1,
                reply_event_ids=frozenset({"prompt-1"}),
            ),
            resources,
            BuzzSettings(private_key="test", allowed_pubkeys=["42"]),  # type: ignore[arg-type]
        )
        assert pending.find(frozenset({"prompt-1"})) is not None

    # No unauthorized click/reply consumes the legitimate pending decision.
    assert broker.resolve(approval_id, approved=False, decided_by="operator")
