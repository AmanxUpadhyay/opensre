"""Scheduled reminder helpers for work items."""

from __future__ import annotations

import json

from config.constants.organization import organization_id
from config.constants.work_items import WORK_ITEM_REMINDER_RUN_AT_PARAM
from config.scope_handoff import acting_scope
from core.domain.work_items import (
    WorkItem,
    WorkItemChannelTarget,
    parse_work_item_datetime,
    resolve_work_item_datetime,
    work_items_path,
)
from infrastructure.scheduling.scheduler.storage import (
    list_tasks,
    patch_task_definitions,
    replace_work_item_reminder,
)
from infrastructure.scheduling.scheduler.types import Provider, ScheduledTask, TaskKind
from tools.system.work_items.validation import validate_provider


def disable_existing_item_reminders(item_id: str) -> int:
    """Disable this work item's enabled reminders in the current owner and store."""
    scope = acting_scope()
    default_owner = organization_id()
    owner = scope.principal.id if scope is not None else default_owner
    store_path = str(work_items_path())
    disabled = 0

    def _matches(task: ScheduledTask) -> bool:
        return (
            task.kind is TaskKind.WORK_ITEM_REMINDER
            and task.params.get("work_item_id", "").strip() == item_id
            and (task.organization or default_owner) == owner
            and (task.params.get("store_path") or store_path) == store_path
        )

    def _disable(current: ScheduledTask) -> dict[str, object]:
        nonlocal disabled
        if not current.enabled or not _matches(current):
            return {}
        disabled += 1
        return {"enabled": False}

    task_ids = [task.id for task in list_tasks() if task.enabled and _matches(task)]
    patch_task_definitions(task_ids, _disable)
    return disabled


def schedule_item_reminder(
    item: WorkItem,
    *,
    targets: list[WorkItemChannelTarget],
    timezone: str,
) -> ScheduledTask | None:
    """Schedule or replace a one-shot work item reminder task."""
    if not item.remind_at:
        return None
    schedule_timezone = timezone.strip() or "UTC"
    parsed_remind_at = parse_work_item_datetime(item.remind_at)
    remind_at = resolve_work_item_datetime(item.remind_at, schedule_timezone)
    if remind_at is None:
        return None
    if parsed_remind_at is not None and parsed_remind_at.tzinfo is not None:
        schedule_timezone = "UTC"
    valid_targets = [target for target in targets if validate_provider(target.provider) is not None]
    if not valid_targets:
        return None
    primary = valid_targets[0]
    parsed_provider = Provider(primary.provider)
    task = ScheduledTask(
        kind=TaskKind.WORK_ITEM_REMINDER,
        cron="",
        timezone=schedule_timezone,
        provider=parsed_provider,
        chat_id=primary.chat_id,
        params={
            "work_item_id": item.id,
            "store_path": str(work_items_path()),
            "disable_after_success": "true",
            WORK_ITEM_REMINDER_RUN_AT_PARAM: remind_at.isoformat(),
            "delivery_targets": json.dumps(
                [target.to_dict() for target in valid_targets], separators=(",", ":")
            ),
        },
    )
    return replace_work_item_reminder(task)


_disable_existing_item_reminders = disable_existing_item_reminders
_schedule_item_reminder = schedule_item_reminder

__all__ = [
    "_disable_existing_item_reminders",
    "_schedule_item_reminder",
    "disable_existing_item_reminders",
    "schedule_item_reminder",
]
