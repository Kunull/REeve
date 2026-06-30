"""
@tool decorator — auto-generates JSON schema from Python type hints.
Handles argument coercion (hex strings → int, "true"/"false" → bool).
"""

from __future__ import annotations

import functools
import inspect
from dataclasses import dataclass, field
from typing import Annotated, Any, Callable, Dict, List, Optional, get_args, get_origin, get_type_hints


@dataclass
class ParameterSchema:
    name: str
    json_type: str          # "string" / "integer" / "boolean" / "number"
    description: str
    required: bool = True


@dataclass
class ToolDefinition:
    name: str
    description: str
    parameters: List[ParameterSchema]
    category: str = "general"
    readonly: bool = True
    mutating: bool = False
    requires_approval: bool = False
    requires_decompiler: bool = False
    timeout: float = 30.0
    handler: Optional[Callable] = None

    def to_anthropic_schema(self) -> dict:
        props: Dict[str, Any] = {}
        required: List[str] = []
        for p in self.parameters:
            props[p.name] = {"type": p.json_type, "description": p.description}
            if p.required:
                required.append(p.name)
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": {
                "type": "object",
                "properties": props,
                "required": required,
            },
        }


def _py_to_json_type(annotation) -> str:
    origin = get_origin(annotation)
    if origin is Annotated:
        inner = get_args(annotation)[0]
        return _py_to_json_type(inner)
    if annotation is int:
        return "integer"
    if annotation is float:
        return "number"
    if annotation is bool:
        return "boolean"
    return "string"


def _coerce(value: Any, json_type: str) -> Any:
    if value is None:
        return value
    if json_type == "integer":
        if isinstance(value, str) and value.startswith(("0x", "0X")):
            return int(value, 16)
        return int(value)
    if json_type == "boolean":
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ("true", "1", "yes")
        return bool(value)
    if json_type == "number":
        return float(value)
    return value


def tool(
    category: str = "general",
    readonly: bool = True,
    mutating: bool = False,
    requires_approval: bool = False,
    requires_decompiler: bool = False,
    timeout: float = 30.0,
):
    """Decorator that registers a function as a tool with auto-generated schema."""
    def decorator(func: Callable) -> Callable:
        hints = get_type_hints(func, include_extras=True)
        sig = inspect.signature(func)
        params: List[ParameterSchema] = []

        for name, param in sig.parameters.items():
            if name in ("self", "cls"):
                continue
            hint = hints.get(name, str)
            description = ""
            if get_origin(hint) is Annotated:
                args = get_args(hint)
                if len(args) >= 2 and isinstance(args[1], str):
                    description = args[1]
            json_type = _py_to_json_type(hint)
            has_default = param.default is not inspect.Parameter.empty
            params.append(ParameterSchema(
                name=name,
                json_type=json_type,
                description=description,
                required=not has_default,
            ))

        defn = ToolDefinition(
            name=func.__name__,
            description=(func.__doc__ or "").strip(),
            parameters=params,
            category=category,
            readonly=readonly,
            mutating=mutating,
            requires_approval=requires_approval,
            requires_decompiler=requires_decompiler,
            timeout=timeout,
        )

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Coerce keyword args
            for p in params:
                if p.name in kwargs:
                    kwargs[p.name] = _coerce(kwargs[p.name], p.json_type)
            return func(*args, **kwargs)

        wrapper._tool_definition = defn
        defn.handler = wrapper
        return wrapper

    return decorator
