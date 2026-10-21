"""Gateway authorization belongs to its configured bot, not the agent turn's tool store."""

from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner

from config.constants import paths
from config.constants.billing import ORGANIZATION_ID_ENV
from config.constants.tenancy import INTEGRATIONS_STORE_PATH_ENV
from config.principal import Actor, Principal, StorageScope
from config.scope_context import bound_storage_scope, current_scope
from gateway.core.middleware.approvals import APPROVE_ACTION_ID, ApprovalBroker
from gateway.transports.discord.approvals import handle_component_interaction
from gateway.transports.discord.dispatcher import DiscordTurnDispatcher
from gateway.transports.discord.events import DiscordInboundMessage
from gateway.transports.discord.settings import load_discord_gateway_settings
from gateway.transports.slack.delivery.approvals import handle_block_actions_payload
from gateway.transports.slack.processing.dispatcher import SlackTurnDispatcher
from gateway.transports.slack.processing.events import SlackInboundMessage
from gateway.transports.slack.settings import load_slack_gateway_settings
from integrations.messaging_policy_store import load_identity_policy
from integrations.messaging_security import MessagingIdentityPolicy
from integrations.store import upsert_instance
from surfaces.cli.commands import messaging as messaging_module


@pytest.fixture
def split_stores(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> StorageScope:
    monkeypatch.setattr(paths, "OPENSRE_HOME_DIR", tmp_path)
    monkeypatch.setattr("integrations.store.STORE_PATH", None)
    monkeypatch.delenv(INTEGRATIONS_STORE_PATH_ENV, raising=False)
    monkeypatch.delenv(paths.CONTEXT_ROOT_ENV, raising=False)
    monkeypatch.setenv(ORGANIZATION_ID_ENV, "org_policy")
    monkeypatch.setenv("SLACK_BOT_TOKEN", "test")
    monkeypatch.setenv("SLACK_APP_TOKEN", "test")
    monkeypatch.setenv("DISCORD_BOT_TOKEN", "test")
    return StorageScope(principal=Principal.org("org_policy"), actor=Actor(id="43"))


@pytest.mark.parametrize("platform", ["slack", "discord"])
def test_cli_revocation_and_pairing_use_same_store_as_dispatcher(
    platform: str, split_stores: StorageScope, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = MessagingIdentityPolicy(inbound_enabled=True, allowed_user_ids=["42"])
    instance = {
        "name": "default",
        "credentials": {"identity_policy": policy.model_dump(mode="json")},
    }
    upsert_instance(platform, instance)
    host_path = paths.integrations_store_path()
    with bound_storage_scope(split_stores):
        upsert_instance(platform, instance)
        org_path = paths.integrations_store_path()
    assert host_path != org_path
    resolver = MagicMock()
    resolved_paths: list[Path] = []

    def rotate(**_kwargs: object) -> object:
        scope = current_scope()
        assert scope is not None and scope.principal == split_stores.principal
        resolved_paths.append(paths.integrations_store_path())
        return object()

    resolver.rotate.side_effect = rotate
    if platform == "slack":
        dispatcher = SlackTurnDispatcher(
            settings=load_slack_gateway_settings(),
            messaging=MagicMock(),
            session_resolver=resolver,
            handler=MagicMock(),
            logger=logging.getLogger(__name__),
        )

        def dispatch(user_id: str, text: str) -> None:
            dispatcher.dispatch(
                SlackInboundMessage(
                    team_id="T1",
                    user_id=user_id,
                    channel_id="C1",
                    ts="1",
                    thread_ts="1",
                    text=text,
                )
            )
    else:
        monkeypatch.setattr(
            "gateway.transports.discord.client.send_message", lambda **_kwargs: None
        )
        dispatcher = DiscordTurnDispatcher(
            settings=load_discord_gateway_settings(),
            bot_token="test",
            session_resolver=resolver,
            handler=MagicMock(),
            logger=logging.getLogger(__name__),
        )

        def dispatch(user_id: str, text: str) -> None:
            dispatcher.dispatch(
                DiscordInboundMessage(
                    guild_id="dm",
                    user_id=user_id,
                    channel_id="C1",
                    message_id="1",
                    thread_id="1",
                    text=text,
                )
            )

    runner = CliRunner()
    result = runner.invoke(messaging_module.messaging, ["revoke", "-p", platform, "-u", "42"])
    assert result.exit_code == 0, result.output

    dispatch("42", "/new")
    resolver.rotate.assert_not_called()

    monkeypatch.setattr(messaging_module, "generate_pairing_code", lambda: "ABC123")
    result = runner.invoke(messaging_module.messaging, ["pair", "-p", platform])
    assert result.exit_code == 0, result.output
    dispatch("43", "/pair ABC123")
    _, host_policy = load_identity_policy(platform)
    assert host_policy.allowed_user_ids == ["43"]
    assert host_policy.pairing_secret_hash is None

    broker = ApprovalBroker()
    approval_id = broker.create(platform=platform, chat_id="C1")
    for user_id, expected in [("42", False), ("43", True)]:
        if platform == "slack":
            resolved = handle_block_actions_payload(
                {
                    "type": "block_actions",
                    "user": {"id": user_id},
                    "channel": {"id": "C1"},
                    "actions": [{"action_id": APPROVE_ACTION_ID, "value": approval_id}],
                },
                broker=broker,
                allowed_user_ids=["42"],
                allow_open_workspace=False,
            )
        else:
            interaction = SimpleNamespace(
                user=SimpleNamespace(id=user_id),
                channel_id="C1",
                data={"custom_id": f"{APPROVE_ACTION_ID}:{approval_id}"},
            )
            resolved = handle_component_interaction(
                interaction,
                broker=broker,
                allowed_user_ids=["42"],  # type: ignore[arg-type]
            )
        assert resolved is expected

    dispatch("43", "/new")
    resolver.rotate.assert_called_once()
    assert resolved_paths == [org_path]
    assert current_scope() is None
    with bound_storage_scope(split_stores):
        _, org_policy = load_identity_policy(platform)
        assert org_policy.allowed_user_ids == ["42"]


@pytest.mark.parametrize("operation", ["load", "pair"])
def test_authorization_restores_turn_scope_after_store_failure(
    operation: str, split_stores: StorageScope, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gateway.core.middleware import identity_policy

    host_path = paths.integrations_store_path()

    def fail(*_args: object, **_kwargs: object) -> object:
        assert current_scope() is None
        assert paths.integrations_store_path() == host_path
        raise OSError("store unavailable")

    target = "load_stored_identity_policy" if operation == "load" else "update_identity_policy"
    monkeypatch.setattr(identity_policy, target, fail)
    with bound_storage_scope(split_stores):
        org_path = paths.integrations_store_path()
        with pytest.raises(OSError, match="store unavailable"):
            if operation == "load":
                identity_policy.load_identity_policy("slack")
            else:
                identity_policy.authorize_pairing(
                    "slack",
                    user_id="43",
                    chat_id="C1",
                    text="/pair ABC123",
                    fallback_allowed_user_ids=[],
                )
        assert current_scope() is split_stores
        assert paths.integrations_store_path() == org_path
    assert current_scope() is None
