"""
EventBus for decoupled communication between engine subsystems.
Used by the TaskExecutor to broadcast task completions and by the
Session to stream progress to the interface layer.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class EventKind(Enum):
    # Task lifecycle
    TASK_STARTED   = "task_started"
    TASK_COMPLETED = "task_completed"
    TASK_FAILED    = "task_failed"

    # Analysis progress
    FUNCTION_ANALYZED   = "function_analyzed"
    IMPORT_RESOLVED     = "import_resolved"
    SIGNATURE_MATCHED   = "signature_matched"
    COMPONENT_FOUND     = "component_found"
    HYPOTHESIS_UPDATED  = "hypothesis_updated"
    NAMES_PROPAGATED    = "names_propagated"

    # LLM interaction
    LLM_TURN_START  = "llm_turn_start"
    LLM_TEXT_DELTA  = "llm_text_delta"
    LLM_TURN_END    = "llm_turn_end"
    LLM_USAGE       = "llm_usage"

    # Tool calls (interactive mode)
    TOOL_CALL_START  = "tool_call_start"
    TOOL_CALL_RESULT = "tool_call_result"
    MUTATION_RECORDED = "mutation_recorded"

    # Session
    SESSION_STARTED   = "session_started"
    SESSION_COMPLETED = "session_completed"
    COST_UPDATE       = "cost_update"

    # Analyst interaction
    ANALYST_MESSAGE = "analyst_message"
    SAVE_GATE       = "save_gate"


@dataclass
class Event:
    kind: EventKind
    data: Dict[str, Any] = field(default_factory=dict)
    session_id: Optional[str] = None


Handler = Callable[[Event], None]


class EventBus:
    """Thread-safe publish/subscribe bus. Handlers are called synchronously."""

    def __init__(self) -> None:
        self._handlers: Dict[EventKind, List[Handler]] = {}
        self._lock = threading.Lock()

    def subscribe(self, kind: EventKind, handler: Handler) -> None:
        with self._lock:
            self._handlers.setdefault(kind, []).append(handler)

    def subscribe_all(self, handler: Handler) -> None:
        """Subscribe to every event kind."""
        for kind in EventKind:
            self.subscribe(kind, handler)

    def unsubscribe(self, kind: EventKind, handler: Handler) -> None:
        with self._lock:
            handlers = self._handlers.get(kind, [])
            if handler in handlers:
                handlers.remove(handler)

    def publish(self, event: Event) -> None:
        with self._lock:
            handlers = list(self._handlers.get(event.kind, []))
        for handler in handlers:
            handler(event)

    def emit(self, kind: EventKind, session_id: Optional[str] = None, **data: Any) -> None:
        self.publish(Event(kind=kind, data=data, session_id=session_id))


# Global bus — subsystems import and use this directly.
# The Session can swap it out with a session-scoped bus.
bus = EventBus()
