"""Regression tests for replacing durable work-item reminders."""

from __future__ import annotations

import dataclasses
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from config.principal import Actor, Principal, StorageScope
from config.scope_context import bound_storage_scope
from core.domain.work_items import (
    WorkItemChannelTarget,
    add_work_item,
    update_work_item,
)
from infrastructure.scheduling.scheduler.agent_runner import AgentPayload
from infrastructure.scheduling.scheduler.runners import SchedulerRunners
from infrastructure.scheduling.scheduler.storage import (
    complete_run,
    get_task,
    list_tasks,
    patch_scheduler_task,
    record_task_success,
    task_store,
    try_claim,
    try_queue_run,
)
from infrastructure.scheduling.scheduler.storage.run_store import get_latest_run_for_fire_time
from infrastructure.scheduling.scheduler.tasks import build_message
from infrastructure.scheduling.scheduler.types import ScheduledTask, TaskReport, TaskStatus
from tools.system.work_items import reminders


@pytest.fixture
def reminder_stores(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    work_items_file = tmp_path / "work_items.json"
    monkeypatch.setattr("core.domain.work_items.store.work_items_path", lambda: work_items_file)
    monkeypatch.setattr(reminders, "work_items_path", lambda: work_items_file)
    monkeypatch.setattr(
        "infrastructure.scheduling.scheduler.storage.task_store.default_task_store_path",
        lambda: tmp_path / "scheduler_tasks.json",
    )
    monkeypatch.setattr(
        "infrastructure.scheduling.scheduler.reload_signal.request_scheduler_reload",
        lambda: None,
    )
    return tmp_path / "scheduler.db"


def _unexpected_agent(_payload: AgentPayload) -> TaskReport:
    raise AssertionError("work-item reminders must not run an agent")


@pytest.mark.parametrize("run_status", [TaskStatus.PENDING, TaskStatus.RUNNING])
def test_rescheduling_same_reminder_keeps_current_run_and_content(
    reminder_stores: Path,
    run_status: TaskStatus,
) -> None:
    item = add_work_item(title="Check clusters", remind_at="2030-01-01T10:00:00Z")
    targets = [WorkItemChannelTarget(provider="slack", chat_id="C999")]
    original = reminders.schedule_item_reminder(item, targets=targets, timezone="UTC")
    assert original is not None
    assert try_queue_run(original.id, item.remind_at, db_path=reminder_stores)
    if run_status is TaskStatus.RUNNING:
        assert try_claim(original.id, item.remind_at, db_path=reminder_stores) is not None
    updated = update_work_item(item.id, changes={"title": "Check production clusters"}).item
    assert updated is not None

    rescheduled = reminders.schedule_item_reminder(updated, targets=targets, timezone="UTC")

    assert rescheduled is not None
    assert rescheduled.id == original.id
    assert rescheduled.enabled is True
    assert [(task.id, task.enabled) for task in list_tasks()] == [(original.id, True)]
    queued = get_latest_run_for_fire_time(original.id, item.remind_at, db_path=reminder_stores)
    assert queued is not None
    assert queued.status is run_status
    if run_status is TaskStatus.RUNNING:
        assert try_claim(rescheduled.id, item.remind_at, db_path=reminder_stores) is None
    message = build_message(rescheduled, SchedulerRunners(agent=_unexpected_agent))
    assert "Task: Check production clusters" in message
    assert "Task: Check clusters" not in message


def test_rescheduling_back_to_prior_time_leaves_one_enabled_reminder(
    reminder_stores: Path,
) -> None:
    item = add_work_item(title="Check clusters", remind_at="2030-01-01T10:00:00Z")
    targets = [WorkItemChannelTarget(provider="slack", chat_id="C999")]
    original = reminders.schedule_item_reminder(item, targets=targets, timezone="UTC")
    assert original is not None
    later = reminders.schedule_item_reminder(
        dataclasses.replace(item, remind_at="2030-01-01T11:00:00Z"),
        targets=targets,
        timezone="UTC",
    )
    assert later is not None
    assert later.id != original.id

    restored = reminders.schedule_item_reminder(item, targets=targets, timezone="UTC")

    assert restored is not None
    assert restored.id not in {original.id, later.id}
    assert restored.enabled is True
    assert {task.id: task.enabled for task in list_tasks()} == {
        original.id: False,
        later.id: False,
        restored.id: True,
    }


def test_rescheduling_same_time_replaces_changed_delivery_targets(reminder_stores: Path) -> None:
    item = add_work_item(title="Check clusters", remind_at="2030-01-01T10:00:00Z")
    primary = WorkItemChannelTarget(provider="slack", chat_id="C999")
    original = reminders.schedule_item_reminder(item, targets=[primary], timezone="UTC")
    assert original is not None

    replacement = reminders.schedule_item_reminder(
        item,
        targets=[primary, WorkItemChannelTarget(provider="telegram", chat_id="12345")],
        timezone="UTC",
    )

    assert replacement is not None
    assert replacement.id != original.id
    assert {task.id: task.enabled for task in list_tasks()} == {
        original.id: False,
        replacement.id: True,
    }
    assert json.loads(replacement.params["delivery_targets"]) == [
        {"provider": "slack", "chat_id": "C999"},
        {"provider": "telegram", "chat_id": "12345"},
    ]


def test_rescheduling_a_retired_tick_uses_a_fresh_execution_identity(
    reminder_stores: Path,
) -> None:
    item = add_work_item(title="Check clusters", remind_at="2030-01-01T10:00:00Z")
    targets = [WorkItemChannelTarget(provider="slack", chat_id="C999")]
    original = reminders.schedule_item_reminder(item, targets=targets, timezone="UTC")
    assert original is not None
    assert try_queue_run(original.id, item.remind_at, db_path=reminder_stores)
    later = reminders.schedule_item_reminder(
        dataclasses.replace(item, remind_at="2030-01-01T11:00:00Z"),
        targets=targets,
        timezone="UTC",
    )
    assert later is not None
    retired = get_latest_run_for_fire_time(original.id, item.remind_at, db_path=reminder_stores)
    assert retired is not None
    assert retired.status is TaskStatus.SKIPPED

    restored = reminders.schedule_item_reminder(item, targets=targets, timezone="UTC")
    repeated = reminders.schedule_item_reminder(item, targets=targets, timezone="UTC")

    assert restored is not None
    assert repeated is not None
    assert restored.id not in {original.id, later.id}
    assert repeated.id == restored.id
    assert {task.id: task.enabled for task in list_tasks()} == {
        original.id: False,
        later.id: False,
        restored.id: True,
    }
    assert try_claim(restored.id, item.remind_at, db_path=reminder_stores) is not None
    assert (
        get_latest_run_for_fire_time(original.id, item.remind_at, db_path=reminder_stores)
        == retired
    )


def test_replacement_keeps_another_organizations_reminder_enabled(
    reminder_stores: Path,
) -> None:
    item = add_work_item(title="Check clusters", remind_at="2030-01-01T10:00:00Z")
    targets = [WorkItemChannelTarget(provider="slack", chat_id="C999")]
    original = reminders.schedule_item_reminder(item, targets=targets, timezone="UTC")
    assert original is not None
    other = task_store.add_task(
        original.model_copy(update={"id": "other-organization", "organization": "another-org"})
    )

    replacement = reminders.schedule_item_reminder(
        dataclasses.replace(item, remind_at="2030-01-01T11:00:00Z"),
        targets=targets,
        timezone="UTC",
    )

    assert replacement is not None
    assert {task.id: task.enabled for task in list_tasks()} == {
        original.id: False,
        other.id: True,
        replacement.id: True,
    }


def test_late_completion_cannot_disable_a_replacement_reminder(reminder_stores: Path) -> None:
    item = add_work_item(title="Check clusters", remind_at="2030-01-01T10:00:00Z")
    targets = [WorkItemChannelTarget(provider="slack", chat_id="C999")]
    original = reminders.schedule_item_reminder(item, targets=targets, timezone="UTC")
    assert original is not None
    claim = try_claim(original.id, item.remind_at, db_path=reminder_stores)
    assert claim is not None
    assert reminders.schedule_item_reminder(
        dataclasses.replace(item, remind_at="2030-01-01T11:00:00Z"),
        targets=targets,
        timezone="UTC",
    )
    restored = reminders.schedule_item_reminder(item, targets=targets, timezone="UTC")
    assert restored is not None
    assert restored.id != original.id

    assert complete_run(claim, status=TaskStatus.SUCCESS, db_path=reminder_stores)
    assert record_task_success(original.id)

    current = get_task(restored.id)
    assert current is not None
    assert current.enabled is True
    assert current.last_run is None
    assert try_claim(restored.id, item.remind_at, db_path=reminder_stores) is not None


def test_concurrent_replacements_leave_one_enabled_reminder(
    reminder_stores: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    item = add_work_item(title="Check clusters", remind_at="2030-01-01T10:00:00Z")
    targets = [WorkItemChannelTarget(provider="slack", chat_id="C999")]
    assert reminders.schedule_item_reminder(item, targets=targets, timezone="UTC")
    ready = threading.Barrier(2)
    stamp_owner = task_store._owned_by_acting_scope

    def _meet_before_store_lock(task: ScheduledTask) -> ScheduledTask:
        stamped = stamp_owner(task)
        ready.wait(timeout=10)
        return stamped

    monkeypatch.setattr(task_store, "_owned_by_acting_scope", _meet_before_store_lock)

    with ThreadPoolExecutor(max_workers=2) as workers:
        pending = [
            workers.submit(
                reminders.schedule_item_reminder,
                dataclasses.replace(item, remind_at=remind_at),
                targets=targets,
                timezone="UTC",
            )
            for remind_at in ("2030-01-01T11:00:00Z", "2030-01-01T12:00:00Z")
        ]
        replacements = [future.result(timeout=15) for future in pending]

    assert all(task is not None for task in replacements)
    enabled = [task for task in list_tasks() if task.enabled]
    assert len(enabled) == 1
    assert enabled[0].id in {task.id for task in replacements if task is not None}


def test_disabling_reminders_preserves_concurrent_scheduler_progress(
    reminder_stores: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    item = add_work_item(title="Check clusters", remind_at="2030-01-01T10:00:00Z")
    original = reminders.schedule_item_reminder(
        item,
        targets=[WorkItemChannelTarget(provider="slack", chat_id="C999")],
        timezone="UTC",
    )
    assert original is not None
    next_run = "2030-01-01T10:00:00+00:00"

    def _list_before_scheduler_progress() -> list[ScheduledTask]:
        snapshot = list_tasks()
        assert patch_scheduler_task(original.id, lambda _current: {"next_run": next_run})
        assert record_task_success(original.id)
        return snapshot

    monkeypatch.setattr(reminders, "list_tasks", _list_before_scheduler_progress)

    reminders.disable_existing_item_reminders(item.id)

    stored = get_task(original.id)
    assert stored is not None
    assert stored.enabled is False
    assert stored.last_run is not None
    assert stored.next_run == next_run


def test_disabling_reminders_stays_in_current_organization_and_work_item_store(
    reminder_stores: Path,
) -> None:
    item = add_work_item(title="Check clusters", remind_at="2030-01-01T10:00:00Z")
    scope = StorageScope(principal=Principal.org("org-a"), actor=Actor(id="operator"))
    with bound_storage_scope(scope):
        original = reminders.schedule_item_reminder(
            item,
            targets=[WorkItemChannelTarget(provider="slack", chat_id="C999")],
            timezone="UTC",
        )
        assert original is not None
        foreign_org = task_store.add_task(
            original.model_copy(update={"id": "another-org", "organization": "org-b"})
        )
        foreign_store = task_store.add_task(
            original.model_copy(
                update={
                    "id": "another-store",
                    "params": {
                        **original.params,
                        "store_path": str(reminder_stores / "other.json"),
                    },
                }
            )
        )

        assert reminders.disable_existing_item_reminders(item.id) == 1

    assert {task.id: task.enabled for task in list_tasks()} == {
        original.id: False,
        foreign_org.id: True,
        foreign_store.id: True,
    }


def test_failed_replacement_preserves_previous_reminder_and_queued_tick(
    reminder_stores: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    item = add_work_item(title="Check clusters", remind_at="2030-01-01T10:00:00Z")
    targets = [WorkItemChannelTarget(provider="slack", chat_id="C999")]
    original = reminders.schedule_item_reminder(item, targets=targets, timezone="UTC")
    assert original is not None
    assert try_queue_run(original.id, item.remind_at, db_path=reminder_stores)

    def _fail_save(_path: Path, _entries: list[dict[str, object]]) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(task_store, "_save_raw", _fail_save)

    with pytest.raises(OSError, match="disk full"):
        reminders.schedule_item_reminder(
            dataclasses.replace(item, remind_at="2030-01-01T11:00:00Z"),
            targets=targets,
            timezone="UTC",
        )

    assert [(task.id, task.enabled) for task in list_tasks()] == [(original.id, True)]
    queued = get_latest_run_for_fire_time(original.id, item.remind_at, db_path=reminder_stores)
    assert queued is not None
    assert queued.status is TaskStatus.PENDING
