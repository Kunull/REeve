"""
Anthropic SDK client — streaming, prompt caching, structured output, retry.
Compatible with anthropic SDK >= 0.40.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Generator, List, Optional

import anthropic

from reeve.llm.base import ChatResponse, LLMClient, Message, StreamChunk, TokenUsage

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3
_RETRY_DELAY = 2.0


def _to_anthropic_messages(messages: List[Message]) -> List[Dict[str, Any]]:
    result = []
    for m in messages:
        if m.tool_calls:
            content: List[Any] = []
            if m.content:
                content.append({"type": "text", "text": m.content})
            for tc in m.tool_calls:
                content.append({
                    "type": "tool_use",
                    "id": tc["id"],
                    "name": tc["name"],
                    "input": tc.get("input", {}),
                })
            result.append({"role": "assistant", "content": content})
        elif m.tool_results:
            content = []
            for tr in m.tool_results:
                content.append({
                    "type": "tool_result",
                    "tool_use_id": tr["tool_use_id"],
                    "content": tr.get("content", ""),
                })
            result.append({"role": "user", "content": content})
        else:
            result.append({"role": m.role, "content": m.content})
    return result


def _build_system_blocks(system: str) -> List[Dict[str, Any]]:
    return [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]


class AnthropicClient(LLMClient):
    def __init__(self, model: str, api_key: Optional[str] = None) -> None:
        self._model = model
        self._client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()

    @property
    def model_id(self) -> str:
        return self._model

    def chat(
        self,
        messages: List[Message],
        tools: List[dict],
        system: str,
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> ChatResponse:
        anthropic_messages = _to_anthropic_messages(messages)
        system_blocks = _build_system_blocks(system)
        kwargs: Dict[str, Any] = {
            "model": self._model,
            "max_tokens": max_tokens,
            "system": system_blocks,
            "messages": anthropic_messages,
        }
        if tools:
            kwargs["tools"] = tools

        for attempt in range(_MAX_RETRIES):
            try:
                response = self._client.messages.create(**kwargs)
                break
            except anthropic.RateLimitError:
                if attempt == _MAX_RETRIES - 1:
                    raise
                time.sleep(_RETRY_DELAY * (attempt + 1))
            except anthropic.APIStatusError as exc:
                if exc.status_code >= 500 and attempt < _MAX_RETRIES - 1:
                    time.sleep(_RETRY_DELAY)
                else:
                    raise

        content_text = ""
        tool_calls: List[Dict[str, Any]] = []
        for block in response.content:
            if block.type == "text":
                content_text += block.text
            elif block.type == "tool_use":
                tool_calls.append({
                    "id": block.id,
                    "name": block.name,
                    "input": block.input,
                })

        u = response.usage
        usage = TokenUsage(
            input_tokens=getattr(u, "input_tokens", 0),
            output_tokens=getattr(u, "output_tokens", 0),
            cache_read_tokens=getattr(u, "cache_read_input_tokens", 0),
            cache_write_tokens=getattr(u, "cache_creation_input_tokens", 0),
        )
        return ChatResponse(
            message=Message(role="assistant", content=content_text, tool_calls=tool_calls),
            usage=usage,
        )

    def chat_stream(
        self,
        messages: List[Message],
        tools: List[dict],
        system: str,
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> Generator[StreamChunk, None, None]:
        anthropic_messages = _to_anthropic_messages(messages)
        system_blocks = _build_system_blocks(system)
        kwargs: Dict[str, Any] = {
            "model": self._model,
            "max_tokens": max_tokens,
            "system": system_blocks,
            "messages": anthropic_messages,
        }
        if tools:
            kwargs["tools"] = tools

        current_tool_id: Optional[str] = None
        current_tool_name: Optional[str] = None

        with self._client.messages.stream(**kwargs) as stream:
            for event in stream:
                event_type = type(event).__name__

                if event_type == "RawContentBlockStartEvent":
                    block = event.content_block
                    if getattr(block, "type", None) == "tool_use":
                        current_tool_id = block.id
                        current_tool_name = block.name
                        yield StreamChunk(
                            is_tool_call_start=True,
                            tool_call_id=current_tool_id,
                            tool_name=current_tool_name,
                        )

                elif event_type == "RawContentBlockDeltaEvent":
                    delta = event.delta
                    delta_type = getattr(delta, "type", None)
                    if delta_type == "text_delta":
                        yield StreamChunk(text=delta.text)
                    elif delta_type == "input_json_delta":
                        yield StreamChunk(
                            tool_args_delta=delta.partial_json,
                            tool_call_id=current_tool_id,
                            tool_name=current_tool_name,
                        )

                elif event_type == "RawContentBlockStopEvent":
                    if current_tool_id:
                        yield StreamChunk(
                            is_tool_call_end=True,
                            tool_call_id=current_tool_id,
                            tool_name=current_tool_name,
                        )
                        current_tool_id = None
                        current_tool_name = None

                elif event_type == "RawMessageDeltaEvent":
                    usage = getattr(event, "usage", None)
                    if usage:
                        yield StreamChunk(usage_output=getattr(usage, "output_tokens", 0))

                elif event_type == "RawMessageStartEvent":
                    msg = getattr(event, "message", None)
                    if msg:
                        usage = getattr(msg, "usage", None)
                        if usage:
                            yield StreamChunk(
                                usage_input=getattr(usage, "input_tokens", 0),
                                cache_read=getattr(usage, "cache_read_input_tokens", 0),
                                cache_write=getattr(usage, "cache_creation_input_tokens", 0),
                            )
