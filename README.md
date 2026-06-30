# REeve

An AI-powered binary reverse engineering assistant. REeve combines Ghidra's static analysis with Claude's reasoning to autonomously analyze binaries — naming functions, identifying vulnerabilities, forming hypotheses, and generating structured reports.

## How it works

REeve runs in two layers:

1. **Static analysis** — Ghidra extracts functions, imports, strings, call graphs, CFG, and type information. No LLM involved here.
2. **LLM reasoning** — Claude receives structured facts from the static pass and reasons about them: naming functions, identifying components, forming hypotheses, and synthesizing a final report.

This separation means the LLM never hallucinates function names or addresses — it only reasons over verified static facts.

## Architecture

```
reeve/
├── host/          # Disassembler abstraction (GhidraHost via PyGhidra)
├── core/          # KnowledgeGraph, Session, EventBus, HypothesisEngine
├── planning/      # GoalPlanner → Task DAG → TaskExecutor + handlers
├── llm/           # AnthropicClient, LLMReasoner, router, cost tracker
├── analysis/      # Static passes: imports, CFG, strings, signatures, types, components
├── tools/         # Tool gateway and individual tools (navigation, decompiler, xrefs)
├── evals/         # Evaluation harness against ground truth
└── ui/            # Textual TUI
```

## Requirements

- Python 3.11+
- [Ghidra](https://ghidra-sre.org/) 11+ with PyGhidra
- Java 21+ (for Ghidra)
- Anthropic API key

## Setup

```bash
pip install -e .

export GHIDRA_INSTALL_DIR=/path/to/ghidra
export ANTHROPIC_API_KEY=sk-ant-...
```

## Usage

```bash
# Full autonomous analysis
reeve analyze ./binary --goal "identify what this binary does and how to exploit it"

# Interactive chat over a binary
reeve chat ./binary

# Single question
reeve ask ./binary "what does the function at 0x401234 do?"

# Export report from a saved session
reeve report session.reeve.json --format md
reeve report session.reeve.json --format html --output report.html
reeve report session.reeve.json --format json
```

## LLM routing

| Task | Model |
|------|-------|
| Function classification | Haiku |
| Function naming / hypothesis formation | Sonnet |
| Global synthesis / report generation | Opus |
