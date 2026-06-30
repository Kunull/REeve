"""LLM provider abstraction — streaming, messages, token usage."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Generator, List, Optional


@dataclass
class Message:
    role: str                                    # "user" / "assistant"
    content: str = ""
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    tool_results: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class StreamChunk:
    text: Optional[str] = None
    is_tool_call_start: bool = False
    is_tool_call_end: bool = False
    tool_call_id: Optional[str] = None
    tool_name: Optional[str] = None
    tool_args_delta: Optional[str] = None
    usage_input: int = 0
    usage_output: int = 0
    cache_read: int = 0
    cache_write: int = 0


@dataclass
class TokenUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

    def __iadd__(self, other: "TokenUsage") -> "TokenUsage":
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cache_read_tokens += other.cache_read_tokens
        self.cache_write_tokens += other.cache_write_tokens
        return self


class LLMClient(ABC):
    @abstractmethod
    def chat(
        self,
        messages: List[Message],
        tools: List[dict],
        system: str,
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> Message: ...

    @abstractmethod
    def chat_stream(
        self,
        messages: List[Message],
        tools: List[dict],
        system: str,
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> Generator[StreamChunk, None, None]: ...

    @property
    @abstractmethod
    def model_id(self) -> str: ...
