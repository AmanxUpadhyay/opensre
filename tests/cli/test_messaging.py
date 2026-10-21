"""Tests for the `opensre messaging` CLI commands."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from integrations.messaging_security import hash_pairing_code, verify_pairing_code
from integrations.store import upsert_instance
from surfaces.cli.commands.messaging import messaging


@pytest.fixture()
def _isolated_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect the integration store to a temp directory."""
    store_path = tmp_path / "integrations.json"
    store_path.write_text(json.dumps({"version": 2, "integrations": []}))
    monkeypatch.setattr("integrations.store.STORE_PATH", store_path)
    return store_path


class TestMessagingPairCommand:
    @pytest.mark.parametrize("platform", ["slack", "discord"])
    def test_first_user_bootstrap_precedes_gateway_and_pairing(
        self, _isolated_store: Path, platform: str
    ) -> None:
        result = CliRunner().invoke(messaging, ["pair", "--platform", platform])

        assert result.exit_code == 0
        output = " ".join(result.output.split())
        allow_step = output.index(f"opensre messaging allow -p {platform} -u")
        gateway_step = output.index("opensre gateway start")
        pair_step = output.index("send: /pair")
        assert allow_step < gateway_step < pair_step

    def test_pair_generates_code(self, _isolated_store: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(messaging, ["pair", "--platform", "telegram"])
        assert result.exit_code == 0
        assert "Pairing code generated" in result.output

    def test_pair_stores_hash_in_integration(self, _isolated_store: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(messaging, ["pair", "--platform", "telegram"])
        assert result.exit_code == 0

        # Read back the store and verify the hash was persisted
        data = json.loads(_isolated_store.read_text())
        integrations = data["integrations"]
        assert len(integrations) == 1
        record = integrations[0]
        assert record["service"] == "telegram"
        creds = record["instances"][0]["credentials"]
        policy_data = creds["identity_policy"]
        assert policy_data["pairing_secret_hash"] is not None
        assert policy_data["inbound_enabled"] is True
        assert policy_data["require_dm_pairing"] is True

    def test_pair_code_is_verifiable(self, _isolated_store: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(messaging, ["pair", "--platform", "discord"])
        assert result.exit_code == 0

        # Extract the code from output (it's between bold markers)
        lines = result.output.strip().split("\n")
        code_line = [line for line in lines if len(line.strip()) == 6 and line.strip().isalnum()]
        assert len(code_line) == 1
        code = code_line[0].strip()

        # Verify the stored hash matches
        data = json.loads(_isolated_store.read_text())
        creds = data["integrations"][0]["instances"][0]["credentials"]
        stored_hash = creds["identity_policy"]["pairing_secret_hash"]
        assert verify_pairing_code(code, stored_hash)

    def test_pair_requires_platform(self) -> None:
        runner = CliRunner()
        result = runner.invoke(messaging, ["pair"])
        assert result.exit_code != 0
        assert "Missing option" in result.output or "required" in result.output.lower()


class TestMessagingAllowCommand:
    def test_allow_adds_user(self, _isolated_store: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(messaging, ["allow", "--platform", "telegram", "--user-id", "12345"])
        assert result.exit_code == 0
        assert "Added user 12345" in result.output

        data = json.loads(_isolated_store.read_text())
        creds = data["integrations"][0]["instances"][0]["credentials"]
        assert "12345" in creds["identity_policy"]["allowed_user_ids"]

    def test_allow_duplicate_user_warns(self, _isolated_store: Path) -> None:
        runner = CliRunner()
        runner.invoke(messaging, ["allow", "--platform", "slack", "--user-id", "U001"])
        result = runner.invoke(messaging, ["allow", "--platform", "slack", "--user-id", "U001"])
        assert result.exit_code == 0
        assert "already in the allowed list" in result.output

    def test_allow_rejects_at_handle(self, _isolated_store: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            messaging, ["allow", "--platform", "telegram", "--user-id", "@opensre_yauhen_bot"]
        )
        assert result.exit_code != 0
        assert "@username" in result.output
        # Nothing should have been persisted for a rejected id.
        data = json.loads(_isolated_store.read_text())
        assert data["integrations"] == []

    def test_allow_rejects_non_numeric_telegram_id(self, _isolated_store: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(messaging, ["allow", "--platform", "telegram", "--user-id", "user1"])
        assert result.exit_code != 0
        assert "numeric" in result.output

    def test_allow_accepts_numeric_telegram_id(self, _isolated_store: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            messaging, ["allow", "--platform", "telegram", "--user-id", " 6514715683 "]
        )
        assert result.exit_code == 0
        assert "Added user 6514715683" in result.output  # normalized (stripped)

    def test_allow_accepts_slack_native_id(self, _isolated_store: Path) -> None:
        # Non-Telegram platforms keep their native id shape (Slack U..., etc.);
        # only the @handle guard applies.
        runner = CliRunner()
        result = runner.invoke(messaging, ["allow", "--platform", "slack", "--user-id", "U12345"])
        assert result.exit_code == 0
        assert "Added user U12345" in result.output


class TestMessagingRevokeCommand:
    def test_revoke_normalizes_input_and_removes_legacy_entries(
        self, _isolated_store: Path
    ) -> None:
        upsert_instance(
            "telegram",
            {
                "name": "default",
                "credentials": {
                    "identity_policy": {
                        "allowed_user_ids": ["@legacy", " @legacy ", "99", "@legacy"],
                        "pairing_secret_hash": hash_pairing_code("ABC123"),
                        "pairing_created_at": time.time(),
                        "pairing_attempts": 2,
                    }
                },
            },
        )

        result = CliRunner().invoke(
            messaging, ["revoke", "--platform", "telegram", "--user-id", " @legacy "]
        )

        assert result.exit_code == 0
        assert "Removed user @legacy" in result.output
        data = json.loads(_isolated_store.read_text())
        policy = data["integrations"][0]["instances"][0]["credentials"]["identity_policy"]
        assert policy["allowed_user_ids"] == ["99"]
        assert policy["pairing_secret_hash"] is None
        assert policy["pairing_created_at"] is None
        assert policy["pairing_attempts"] == 0

    def test_revoke_removes_user(self, _isolated_store: Path) -> None:
        runner = CliRunner()
        # First add a user
        runner.invoke(messaging, ["allow", "--platform", "telegram", "--user-id", "99"])
        # Then revoke
        result = runner.invoke(messaging, ["revoke", "--platform", "telegram", "--user-id", "99"])
        assert result.exit_code == 0
        assert "Removed user 99" in result.output

        data = json.loads(_isolated_store.read_text())
        creds = data["integrations"][0]["instances"][0]["credentials"]
        assert "99" not in creds["identity_policy"]["allowed_user_ids"]

    def test_revoke_nonexistent_user_warns(self, _isolated_store: Path) -> None:
        runner = CliRunner()
        before = _isolated_store.read_bytes()
        result = runner.invoke(messaging, ["revoke", "--platform", "discord", "--user-id", "ghost"])
        assert result.exit_code == 0
        assert "not in the allowed list" in result.output
        assert _isolated_store.read_bytes() == before


class TestMessagingStatusCommand:
    @pytest.mark.parametrize("explicit_policy", [False, True])
    def test_status_uses_runtime_inbound_default(
        self, _isolated_store: Path, explicit_policy: bool
    ) -> None:
        credentials: dict[str, Any] = {"bot_token": "synthetic-secret-token"}
        if explicit_policy:
            credentials["identity_policy"] = {}
        upsert_instance("telegram", {"name": "default", "credentials": credentials})
        before = _isolated_store.read_bytes()

        result = CliRunner().invoke(messaging, ["status", "--platform", "telegram"])

        assert result.exit_code == 0
        expected = "No" if explicit_policy else "Yes"
        assert f"Inbound enabled: {expected}" in " ".join(result.output.split())
        source = "Stored policy" if explicit_policy else "Defaults (no stored policy)"
        assert f"Policy source: {source}" in " ".join(result.output.split())
        if not explicit_policy:
            assert "Environment settings may affect gateway authorization" in result.output
        assert "synthetic-secret-token" not in result.output
        assert "connected" not in result.output.lower()
        assert _isolated_store.read_bytes() == before

    @pytest.mark.parametrize(
        ("secret", "age_seconds", "attempts", "expected"),
        [
            (False, None, 0, "Absent"),
            (True, 0, 0, "Valid"),
            (True, 901, 0, "Expired"),
            (True, None, 0, "Expired"),
            (True, 0, 5, "Exhausted"),
        ],
    )
    def test_status_reports_usable_pairing_state_without_secrets(
        self,
        _isolated_store: Path,
        secret: bool,
        age_seconds: int | None,
        attempts: int,
        expected: str,
    ) -> None:
        stored_hash = hash_pairing_code("ABC123")
        upsert_instance(
            "telegram",
            {
                "name": "default",
                "credentials": {
                    "identity_policy": {
                        "pairing_secret_hash": stored_hash if secret else None,
                        "pairing_created_at": (
                            time.time() - age_seconds if age_seconds is not None else None
                        ),
                        "pairing_attempts": attempts,
                    }
                },
            },
        )
        before = _isolated_store.read_bytes()

        result = CliRunner().invoke(messaging, ["status", "--platform", "telegram"])

        assert result.exit_code == 0
        assert f"Pairing code: {expected}" in " ".join(result.output.split())
        assert stored_hash not in result.output
        assert "ABC123" not in result.output
        assert _isolated_store.read_bytes() == before

    def test_status_no_integration(self, _isolated_store: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(messaging, ["status", "--platform", "telegram"])
        assert result.exit_code == 0
        assert "No telegram integration configured" in result.output

    def test_status_with_configured_integration(self, _isolated_store: Path) -> None:
        runner = CliRunner()
        # Set up a user first (Telegram ids are numeric)
        runner.invoke(messaging, ["allow", "--platform", "telegram", "--user-id", "6514715683"])
        result = runner.invoke(messaging, ["status", "--platform", "telegram"])
        assert result.exit_code == 0
        assert "Inbound enabled" in result.output
        assert "6514715683" in result.output


class TestMessagingGroupNoSubcommand:
    def test_bare_group_shows_help_and_exits_zero(self) -> None:
        # A bare group is a help request, not an error — must exit 0 (not Click's 2)
        # so the interactive shell doesn't surface a scary "non-zero code" line.
        runner = CliRunner()
        result = runner.invoke(messaging, [])
        assert result.exit_code == 0
        assert "Commands:" in result.output
        for sub in ("allow", "pair", "revoke", "status"):
            assert sub in result.output

    def test_pair_message_points_to_platform_not_shell(self, _isolated_store: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(messaging, ["pair", "--platform", "telegram"])
        assert result.exit_code == 0
        assert "not this shell" in result.output
        assert "/pair" in result.output
        assert "gateway" in result.output.lower()


@pytest.mark.parametrize("multiple_records", [False, True])
@pytest.mark.parametrize("command", ["pair", "allow", "revoke", "status"])
def test_ambiguous_integrations_fail_without_changes(
    _isolated_store: Path, multiple_records: bool, command: str
) -> None:
    instance = {"name": "first", "credentials": {"bot_token": "synthetic-secret-token"}}
    records: list[dict[str, Any]] = [
        {"id": "telegram-first", "service": "telegram", "status": "active", "instances": [instance]}
    ]
    if multiple_records:
        records.append(
            {
                "id": "telegram-second",
                "service": "telegram",
                "status": "active",
                "instances": [{"name": "second", "credentials": {}}],
            }
        )
    else:
        records[0]["instances"].append({"name": "second", "credentials": {}})
    _isolated_store.write_text(json.dumps({"version": 2, "integrations": records}))
    before = _isolated_store.read_bytes()
    arguments = [command, "--platform", "telegram"]
    if command in {"allow", "revoke"}:
        arguments.extend(["--user-id", "99"])

    result = CliRunner().invoke(messaging, arguments)

    assert result.exit_code != 0
    assert "Error:" in result.output
    assert "multiple" in result.output.lower()
    assert "opensre integrations" in " ".join(result.output.split())
    assert "synthetic-secret-token" not in result.output
    assert _isolated_store.read_bytes() == before
