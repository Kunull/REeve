# REeve

An AI-powered binary reverse engineering **assistant**. REeve combines Ghidra's static analysis with Claude's reasoning to autonomously analyze binaries — naming functions, identifying vulnerabilities, forming hypotheses, and generating structured reports.

> Submitted to Black Hat Arsenal India 2026.

---

## Why REeve

Existing AI-RE tools fall into two patterns:

- **Fixed pipelines** (e.g. Kong): run the same analysis steps regardless of goal — wasteful and inflexible.
- **Reactive LLM loops** (e.g. Rikugan): ask the LLM what to do next — burns tokens on coordination, hallucinates function names.

REeve does neither. It builds a **goal-driven task DAG** from a plain-English objective, runs static analysis first to collect ground truth (no hallucination), then routes only the semantic residuals to the LLM.

---

## Architecture

```
reeve/
├── host/          # Disassembler abstraction — GhidraHost via PyGhidra
├── core/          # KnowledgeGraph · Session · EventBus · HypothesisEngine
├── planning/      # GoalPlanner → Task DAG → TaskExecutor + handlers
├── llm/           # AnthropicClient · LLMReasoner · tiered router · cost tracker
├── analysis/      # Static passes: imports · CFG · strings · signatures · types · components
├── tools/         # Tool gateway and individual tools (navigation, decompiler, xrefs)
├── evals/         # Evaluation harness against ground truth JSON
└── ui/            # Textual TUI
```

### Two-layer pipeline

**Layer 1 — Static analysis (no LLM, no cost)**
Ghidra extracts: functions, imports, strings, call graph, CFG, xrefs, type hints, component clusters, known library signatures (stdlib, crypto, network protocols).
All facts land in a queryable **KnowledgeGraph** with confidence scores and provenance.

**Layer 2 — LLM reasoning (structured input, no hallucination)**
Claude receives verified static facts — not raw decompilation alone — and reasons about them. The LLM names functions, identifies vulnerability classes, forms testable hypotheses, and writes the final report. It cannot invent addresses or function names because the graph is the ground truth.

### LLM routing

| Task | Model | Reason |
|------|-------|--------|
| Function classification | Haiku | Fast, cheap, rule-like |
| Function naming · hypothesis formation | Sonnet | Nuanced reasoning |
| Global synthesis · report generation | Opus | Full binary context |

---

## Demo

Running on a CTF heap-exploitation binary (`enterprising-echo`):

```
$ reeve analyze ./binary --goal "identify what it does and how to exploit it"

Session b29c1b20
  Functions : 76 total · 75 named · 16 resolved via signatures
  Components: 2   Hypotheses: 2
  Cost      : $0.041
```

**Excerpt from generated report:**

> **Vulnerability:** tcache poisoning via use-after-free. The `print_tcache` /
> `print_chunk` interface exposes raw `fd` pointers and the only safety check
> (`is_mapped` via `mincore`) validates mapping but not chunk legitimacy —
> a forged freelist entry that lands in mapped memory is happily returned
> by the allocator.
>
> **Exploitation path:** free a chunk → overwrite its `fd` via UAF write →
> allocate twice to obtain a controlled pointer → write `&win` (0x101a22)
> into a GOT/function-pointer slot → trigger → flag.

---

## Requirements

- Python 3.11+
- [Ghidra](https://ghidra-sre.org/) 11+ with PyGhidra
- Java 21+ (Temurin recommended)
- Anthropic API key

---

## Setup

```bash
export JAVA_HOME=/path/to/jdk-21
export GHIDRA_INSTALL_DIR=/path/to/ghidra_PUBLIC
export ANTHROPIC_API_KEY=sk-ant-...

bash setup.sh
```

Or manually:

```bash
pip install -e .
```

---

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

---

## Goals supported out of the box

| Goal keyword | Plan generated |
|---|---|
| `malware` / `c2` | imports → CFG → strings → network hypothesis → report |
| `vulnerability` / `exploit` | imports → call graph → CFG → type inference → vuln hypothesis → report |
| `symbols` / `name` | call graph → signatures → function analysis → propagate names |
| *(default)* | full static foundation + function analysis + synthesis + report |
