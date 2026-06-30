"""Cost tracking — accumulates per-model token usage and converts to USD."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict

from reeve.llm.base import TokenUsage


# Prices per 1M tokens as of early 2025 (USD)
_PRICING: Dict[str, Dict[str, float]] = {
    "claude-haiku-4-5-20251001": {
        "input": 0.80, "output": 4.00, "cache_write": 1.00, "cache_read": 0.08,
    },
    "claude-sonnet-4-6": {
        "input": 3.00, "output": 15.00, "cache_write": 3.75, "cache_read": 0.30,
    },
    "claude-opus-4-8": {
        "input": 15.00, "output": 75.00, "cache_write": 18.75, "cache_read": 1.50,
    },
}
_DEFAULT_PRICING = {"input": 3.00, "output": 15.00, "cache_write": 3.75, "cache_read": 0.30}


def _cost_usd(usage: TokenUsage, model_id: str) -> float:
    p = _PRICING.get(model_id, _DEFAULT_PRICING)
    return (
        usage.input_tokens * p["input"]
        + usage.output_tokens * p["output"]
        + usage.cache_write_tokens * p["cache_write"]
        + usage.cache_read_tokens * p["cache_read"]
    ) / 1_000_000


@dataclass
class CostTracker:
    _per_model: Dict[str, TokenUsage] = field(default_factory=dict)
    _ceiling_usd: float = float("inf")

    def record(self, model_id: str, usage: TokenUsage) -> None:
        if model_id not in self._per_model:
            self._per_model[model_id] = TokenUsage()
        self._per_model[model_id] += usage

    @property
    def total_cost_usd(self) -> float:
        return sum(_cost_usd(u, m) for m, u in self._per_model.items())

    @property
    def total_tokens(self) -> TokenUsage:
        total = TokenUsage()
        for u in self._per_model.values():
            total += u
        return total

    def set_ceiling(self, usd: float) -> None:
        self._ceiling_usd = usd

    def budget_remaining(self) -> float:
        return max(0.0, self._ceiling_usd - self.total_cost_usd)

    def over_budget(self) -> bool:
        return self.total_cost_usd >= self._ceiling_usd

    def summary(self) -> str:
        lines = [f"Total cost: ${self.total_cost_usd:.4f}"]
        for model, usage in self._per_model.items():
            cost = _cost_usd(usage, model)
            lines.append(
                f"  {model}: in={usage.input_tokens} out={usage.output_tokens} "
                f"cache_r={usage.cache_read_tokens} cache_w={usage.cache_write_tokens} "
                f"${cost:.4f}"
            )
        return "\n".join(lines)
