"""CLI commands for messaging security: DM pairing and identity management."""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager

import click
from rich.console import Console
from rich.markup import escape

from infrastructure.terminal.theme import DIM, HIGHLIGHT, SECONDARY, WARNING
from integrations.messaging_policy_store import (
    AmbiguousMessagingIntegration,
    load_identity_policy,
    update_identity_policy,
)
from integrations.messaging_security import (
    MessagingIdentityPolicy,
    generate_pairing_code,
    hash_pairing_code,
    pairing_code_status,
)
from surfaces.shared.messaging_options import messaging_parameters, validate_allow_user_id

_console = Console(highlight=False)


@contextmanager
def _identity_policy_errors() -> Iterator[None]:
    """Present ambiguous integration selections as actionable CLI errors."""
    try:
        yield
    except AmbiguousMessagingIntegration as exc:
        raise click.ClickException(
            f"{exc} Inspect the configuration with `opensre integrations list`."
        ) from exc


@click.group("messaging", invoke_without_command=True)
@click.pass_context
def messaging(ctx: click.Context) -> None:
    """Messaging security: DM pairing and identity management."""
    # No subcommand: show help and exit 0 (a bare group is a help request here,
    # not an error) instead of Click's default missing-command exit code 2.
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@messaging.command("pair", params=messaging_parameters("pair"))
def pair_command(platform: str) -> None:
    """Generate a one-time pairing code for DM authentication.

    The operator runs this command, receives a code, and sends it to the
    bot via DM as `/pair <code>`. On success the bot adds the sender to
    the allowed-users list.
    """
    service = platform.lower()
    code = generate_pairing_code()

    def generate(policy: MessagingIdentityPolicy) -> tuple[bool, bool]:
        was_disabled = not policy.inbound_enabled
        policy.pairing_secret_hash = hash_pairing_code(code)
        policy.pairing_created_at = time.time()
        policy.pairing_attempts = 0
        policy.require_dm_pairing = True
        policy.inbound_enabled = True
        return was_disabled, bool(policy.allowed_user_ids)

    with _identity_policy_errors():
        was_disabled, has_allowed_users = update_identity_policy(service, generate)

    if was_disabled:
        _console.print(f"[{WARNING}]Note: inbound messaging has been enabled for {platform}.[/]")
    _console.print(f"\n[bold {HIGHLIGHT}]Pairing code generated for {platform}:[/]")
    _console.print(f"\n  [bold {HIGHLIGHT}]{code}[/]\n")
    if service in {"slack", "discord"} and not has_allowed_users:
        _console.print(
            f"[{WARNING}]First-time setup: allow one trusted user before starting "
            f"the {platform} gateway. A pairing code alone is not enough.[/]"
        )
        _console.print(f"  opensre messaging allow -p {service} -u <your-user-id>")
    _console.print(
        f"[{SECONDARY}]The {platform} gateway must be running to receive pairing messages. "
        "Start it with `opensre gateway start`.[/]"
    )
    _console.print(
        f"Next: have the user you want to add open [bold]{platform}[/bold] "
        f"(not this shell), DM your bot, and send: /pair {code}"
    )
    _console.print(
        f"[{DIM}]Share the code privately. It is single-use and expires in 15 minutes.[/]\n"
    )


@messaging.command("allow", params=messaging_parameters("allow"))
def allow_command(platform: str, user_id: str) -> None:
    """Manually add a user to the allowed-users list (bypasses DM pairing)."""
    service = platform.lower()
    user_id = validate_allow_user_id(service, user_id)

    def allow(policy: MessagingIdentityPolicy) -> tuple[bool, bool]:
        if user_id in policy.allowed_user_ids:
            return False, False
        was_disabled = not policy.inbound_enabled
        policy.allowed_user_ids.append(user_id)
        policy.inbound_enabled = True
        return True, was_disabled

    with _identity_policy_errors():
        added, was_disabled = update_identity_policy(service, allow)

    if not added:
        _console.print(
            f"[{WARNING}]User {escape(user_id)} is already in the allowed list for {platform}.[/]"
        )
        return

    if was_disabled:
        _console.print(f"[{WARNING}]Note: inbound messaging has been enabled for {platform}.[/]")

    _console.print(f"[{HIGHLIGHT}]Added user {escape(user_id)} to {platform} allowed list.[/]")


@messaging.command("revoke", params=messaging_parameters("revoke"))
def revoke_command(platform: str, user_id: str) -> None:
    """Remove a user from the allowed-users list."""
    service = platform.lower()
    user_id = user_id.strip()

    def revoke(policy: MessagingIdentityPolicy) -> bool:
        remaining = [uid for uid in policy.allowed_user_ids if uid.strip() != user_id]
        if remaining == policy.allowed_user_ids:
            return False
        policy.allowed_user_ids = remaining
        # Invalidate outstanding codes so a revoked user cannot re-pair with one.
        policy.pairing_secret_hash = None
        policy.pairing_created_at = None
        policy.pairing_attempts = 0
        return True

    with _identity_policy_errors():
        removed = update_identity_policy(service, revoke)

    if not removed:
        _console.print(
            f"[{WARNING}]User {escape(user_id)} is not in the allowed list for {platform}.[/]"
        )
        return

    _console.print(f"[{HIGHLIGHT}]Removed user {escape(user_id)} from {platform} allowed list.[/]")


@messaging.command("status", params=messaging_parameters("status"))
def status_command(platform: str) -> None:
    """Show the current messaging security status for a platform."""
    service = platform.lower()
    with _identity_policy_errors():
        record, policy = load_identity_policy(service)

    _console.print(f"\n[bold]Messaging Security Status — {platform}[/bold]\n")

    if record is None:
        _console.print(f"[{WARNING}]No {platform} integration configured.[/]")
        _console.print(f"[{DIM}]Run the setup wizard or configure the integration first.[/]\n")
        return

    has_stored_policy = record.get("credentials", {}).get("identity_policy") is not None
    source = "Stored policy" if has_stored_policy else "Defaults (no stored policy)"
    _console.print(f"  Policy source:       {source}")
    _console.print(f"[{SECONDARY}]Authorization policy only; gateway connectivity not checked.[/]")
    if not has_stored_policy:
        _console.print(
            f"[{SECONDARY}]Environment settings may affect gateway authorization "
            "until a policy is saved.[/]"
        )
    _console.print()
    _console.print(f"  Inbound enabled:     {'Yes' if policy.inbound_enabled else 'No'}")
    _console.print(f"  DM pairing required: {'Yes' if policy.require_dm_pairing else 'No'}")
    _console.print(f"  Pairing code:        {pairing_code_status(policy).capitalize()}")
    _console.print(f"  Rejection behavior:  {policy.rejection_behavior.value}")
    _console.print(f"  Allowed users:       {len(policy.allowed_user_ids)}")
    if policy.allowed_user_ids:
        for uid in policy.allowed_user_ids:
            _console.print(f"    - {uid}", markup=False)
    _console.print(f"  Allowed chats:       {len(policy.allowed_chat_ids)}")
    if policy.allowed_chat_ids:
        for cid in policy.allowed_chat_ids:
            _console.print(f"    - {cid}", markup=False)
    _console.print()
