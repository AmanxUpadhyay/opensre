"""Startup settings distinguish absent policy from an explicit empty allowlist."""

from __future__ import annotations

import importlib

import pytest

from gateway.core.lifecycle.errors import GatewayConfigurationError
from integrations.store import upsert_instance


@pytest.mark.parametrize("platform", ["slack", "discord", "telegram", "buzz"])
def test_stored_empty_policy_does_not_fall_back_to_environment(
    platform: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = importlib.import_module(f"gateway.transports.{platform}.settings")
    monkeypatch.setenv(
        f"{platform.upper()}_ALLOWED_USERS" if platform != "buzz" else "BUZZ_ALLOWED_PUBKEYS", "42"
    )
    monkeypatch.setenv(f"{platform.upper()}_BOT_TOKEN", "test")
    monkeypatch.setenv("SLACK_APP_TOKEN", "test")
    monkeypatch.setenv("BUZZ_PRIVATE_KEY", "test")
    monkeypatch.delenv("SLACK_ALLOW_OPEN_WORKSPACE", raising=False)
    monkeypatch.delenv("DISCORD_ALLOW_OPEN_GUILD", raising=False)
    upsert_instance(platform, {"name": "default", "credentials": {"identity_policy": {}}})
    load = getattr(
        module,
        f"load_{platform}_gateway_settings"
        if platform in {"slack", "discord"}
        else "load_gateway_settings",
    )

    if platform in {"slack", "discord"}:
        with pytest.raises(GatewayConfigurationError, match="needs allowed users"):
            load()
    else:
        settings = load()
        assert (
            getattr(settings, "allowed_pubkeys" if platform == "buzz" else "allowed_user_ids") == []
        )
