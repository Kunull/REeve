"""
TaskExecutor — runs the task DAG with dependency ordering.
Independent tasks run in parallel via a thread pool; dependent tasks wait.
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from typing import TYPE_CHECKING, Callable, Dict, List, Optional, Set

from reeve.core.events import EventKind, bus
from reeve.planning.tasks import Task, TaskKind, TaskResult, TaskStatus

if TYPE_CHECKING:
    from reeve.core.session import Session

logger = logging.getLogger(__name__)

# Handlers registered by subsystems to run specific task kinds
TaskHandler = Callable[["Session", Task], TaskResult]
_HANDLERS: Dict[TaskKind, TaskHandler] = {}


def register_handler(kind: TaskKind) -> Callable[[TaskHandler], TaskHandler]:
    def decorator(fn: TaskHandler) -> TaskHandler:
        _HANDLERS[kind] = fn
        return fn
    return decorator


class TaskExecutor:
    def __init__(self, session: "Session", max_workers: int = 4) -> None:
        self._session = session
        self._pool = ThreadPoolExecutor(max_workers=max_workers)
        self._tasks: Dict[str, Task] = {}
        self._futures: Dict[str, Future] = {}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

    def submit_all(self, tasks: List[Task]) -> None:
        with self._lock:
            for t in tasks:
                self._tasks[t.id] = t

    def run(self) -> None:
        """Run tasks until all complete or a stop is requested."""
        while not self._stop_event.is_set():
            ready = self._get_ready_tasks()
            if not ready:
                # Check if everything is done
                with self._lock:
                    pending = [
                        t for t in self._tasks.values()
                        if t.status in (TaskStatus.PENDING, TaskStatus.RUNNING)
                    ]
                if not pending:
                    break
                # Wait briefly for in-flight tasks to complete
                completed_any = False
                for fid, future in list(self._futures.items()):
                    if future.done():
                        completed_any = True
                if not completed_any:
                    import time
                    time.sleep(0.05)
                continue

            for task in ready:
                self._launch(task)

        # Wait for all in-flight futures
        for future in self._futures.values():
            try:
                future.result()
            except Exception:
                pass

    def stop(self) -> None:
        self._stop_event.set()

    def _get_ready_tasks(self) -> List[Task]:
        with self._lock:
            ready = []
            for task in self._tasks.values():
                if task.status != TaskStatus.PENDING:
                    continue
                if task.id in self._futures:
                    continue
                deps_met = all(
                    self._tasks.get(dep_id, Task(kind=TaskKind.RESOLVE_IMPORTS)).status
                    == TaskStatus.COMPLETED
                    for dep_id in task.depends_on
                )
                deps_failed = any(
                    self._tasks.get(dep_id, Task(kind=TaskKind.RESOLVE_IMPORTS)).status
                    == TaskStatus.FAILED
                    for dep_id in task.depends_on
                )
                if deps_failed:
                    task.status = TaskStatus.SKIPPED
                    continue
                if deps_met:
                    ready.append(task)
            return ready

    def _launch(self, task: Task) -> None:
        with self._lock:
            if task.status != TaskStatus.PENDING:
                return
            task.status = TaskStatus.RUNNING

        bus.emit(EventKind.TASK_STARTED, session_id=self._session.id, task_id=task.id, task_kind=task.kind.value)
        future = self._pool.submit(self._run_task, task)
        with self._lock:
            self._futures[task.id] = future

    def _run_task(self, task: Task) -> None:
        handler = _HANDLERS.get(task.kind)
        try:
            if handler is None:
                logger.warning("No handler for task kind %s — skipping", task.kind)
                task.status = TaskStatus.SKIPPED
                return

            if self._session.cost_tracker.over_budget():
                logger.warning("Over budget — skipping %s", task.kind)
                task.status = TaskStatus.SKIPPED
                return

            result = handler(self._session, task)
            task.result = result
            task.status = TaskStatus.COMPLETED if result.success else TaskStatus.FAILED
            task.error = result.error

            bus.emit(
                EventKind.TASK_COMPLETED,
                session_id=self._session.id,
                task_id=task.id,
                task_kind=task.kind.value,
                success=result.success,
            )

            # Add any follow-on tasks
            if result.spawned_tasks:
                self.submit_all(result.spawned_tasks)

        except Exception as exc:
            task.status = TaskStatus.FAILED
            task.error = str(exc)
            logger.exception("Task %s failed: %s", task.kind, exc)
            bus.emit(EventKind.TASK_FAILED, session_id=self._session.id, task_id=task.id, error=str(exc))

    def summary(self) -> Dict[str, int]:
        with self._lock:
            counts: Dict[str, int] = {}
            for t in self._tasks.values():
                counts[t.status.value] = counts.get(t.status.value, 0) + 1
        return counts
