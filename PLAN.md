# AI Reversing Engine — Architecture

---

## Core Thesis

Both Kong and Rikugan treat the LLM as the primary reasoning engine that reads raw decompiler output. This is the root cause of their main failure modes: expensive per-function LLM calls, shallow reasoning without program-wide context, and results that degrade on obfuscated or large binaries.

The right inversion: **static analysis does the reasoning; the LLM resolves residual semantic ambiguity.**

The engine runs program analysis first — type inference, dataflow, import resolution, pattern matching — builds a structured model of what it knows with confidence scores, then calls the LLM only to interpret what static analysis cannot. The LLM receives structured facts, not raw pseudocode.

The second fundamental difference: instead of a fixed pipeline (Kong) or a purely reactive loop (Rikugan), this engine uses a **goal-driven task planner**. The user states an objective; the planner decomposes it into analysis tasks with dependencies; the executor runs them in order, spawning new tasks from discoveries. This handles both fully automated batch runs and live analyst collaboration in the same model.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                          Interface Layer                             │
│  ┌───────────────┐    ┌─────────────────────┐    ┌────────────────┐  │
│  │  CLI / TUI    │    │  IDA / BN  Plugin   │    │  MCP Server    │  │
│  └───────┬───────┘    └──────────┬──────────┘    └───────┬────────┘  │
└──────────┼───────────────────────┼────────────────────────┼──────────┘
           │                       │                        │
           └───────────────────────┼────────────────────────┘
                                   │
┌──────────────────────────────────▼───────────────────────────────────┐
│                           Session Layer                              │
│  SessionManager  ·  GoalPlanner  ·  TaskExecutor  ·  EventBus        │
└──────────────────────────────────┬───────────────────────────────────┘
                                   │
           ┌───────────────────────┼────────────────────────┐
           │                       │                        │
           ▼                       ▼                        ▼
┌─────────────────┐    ┌───────────────────────┐    ┌──────────────────┐
│ ProgramAnalyzer │    │   KnowledgeGraph       │    │  LLMReasoner     │
│                 │    │                        │    │                  │
│ · type infer    │───▶│ Functions, Types,      │◀───│ · interprets     │
│ · dataflow      │    │ Strings, Hypotheses,   │    │   structured     │
│ · CFG analysis  │    │ Evidence, Components   │    │   facts          │
│ · pattern match │    │                        │    │ · tiered model   │
│ · import resolve│    │ (live, queryable,       │    │   routing        │
│ · signature DB  │    │  evidence-scored)       │    │                  │
└─────────────────┘    └───────────────────────┘    └──────────────────┘
                                   │
┌──────────────────────────────────▼───────────────────────────────────┐
│                           Tool Gateway                               │
│  Analysis Tools · Mutation Tools · Symbolic Tools · Script Gate      │
└──────────────────────────────────┬───────────────────────────────────┘
                                   │
┌──────────────────────────────────▼───────────────────────────────────┐
│                           Host Bridge                                │
│            GhidraHost  ·  IDAHost  ·  BinaryNinjaHost                │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Subsystems

### 1. Knowledge Graph

The central data structure of the engine. Everything the agent knows about a binary lives here. Neither a flat JSON file (Kong) nor a Markdown dump (Rikugan) — a live, queryable, evidence-scored graph.

#### Node Types

| Node | Key Fields |
|------|-----------|
| `FunctionNode` | address, name, prototype, component, size_class, source_lang |
| `TypeNode` | name, kind (struct/enum/typedef), fields, size |
| `StringNode` | address, value, encoding, xref_functions |
| `ComponentNode` | name, purpose, member_functions |
| `ImportNode` | name, library, resolved_address |
| `HypothesisNode` | claim, confidence, evidence_ids, status (open/confirmed/refuted) |

#### Edge Types

| Edge | Meaning |
|------|---------|
| `CALLS` | function → function |
| `REFERENCES` | function → string/data |
| `USES_TYPE` | function → type |
| `MEMBER_OF` | function → component |
| `EVIDENCE_FOR` | evidence → hypothesis |
| `DERIVED_FROM` | fact → source fact (propagation chain) |

#### Evidence Model

Every fact carries:
```python
@dataclass
class Fact:
    value: Any
    confidence: float        # 0.0 – 1.0
    source: FactSource       # STATIC_ANALYSIS | SIGNATURE_MATCH | LLM | ANALYST
    evidence: List[str]      # human-readable evidence descriptions
    dirty: bool              # True if a dependency changed and re-analysis is needed
```

When an analyst renames a function or the LLM resolves a type, affected downstream facts are marked `dirty`. The task planner can then re-analyze dirty nodes on demand or proactively.

#### Query Interface

The KnowledgeGraph is queryable, not just writable:
```python
graph.find_functions(calls="recv", confidence_above=0.7)
graph.find_components(purpose_contains="crypto")
graph.get_evidence_chain(function_address=0x401000)
graph.unresolved_functions(size_class="medium")
```

This lets the planner make directed analysis decisions rather than exhaustive sweeps.

---

### 2. Goal Planner + Task Executor

The engine accepts a goal statement (from CLI, plugin, or autonomously inferred). The planner decomposes it into a dependency graph of analysis tasks. The executor runs them — parallelizing independent tasks, serializing dependent ones, and dynamically adding new tasks as discoveries warrant.

#### Goal Examples

```
"Analyze this binary for malware behavior"
"Find where user input is processed"
"Recover all function names and types"
"What is the purpose of sub_401a30?"
"Remove the license check"
```

#### Task Types

| Task | Input | Output | LLM? |
|------|-------|--------|------|
| `ResolveImports` | binary | ImportNode set | No |
| `BuildCallGraph` | binary | call graph edges | No |
| `ClassifyFunctions` | function list | size_class, source_lang | No |
| `MatchSignatures` | function set | resolved FunctionNodes | No |
| `InferTypes` | call graph + imports | TypeNode proposals | No |
| `PropagateNames` | resolved set + call graph | dirty-mark callers | No |
| `AnalyzeFunction` | FunctionNode + context | updated FunctionNode | **Yes** |
| `FormHypothesis` | component / pattern | HypothesisNode | **Yes** |
| `TestHypothesis` | hypothesis | evidence + confidence delta | Mixed |
| `SynthesizeComponent` | ComponentNode + members | component summary | **Yes** |
| `GlobalSynthesis` | full graph | naming unified, structs synthesized | **Yes** |
| `DeobfuscateFunction` | obfuscated FunctionNode | cleaned CFG + annotations | Mixed |
| `GenerateReport` | goal + graph state | structured report | **Yes** |

The key observation: the first six task types require no LLM at all. They are pure static analysis. LLM calls are reserved for tasks where semantic interpretation is genuinely required.

#### Task Execution

```python
class TaskExecutor:
    def submit(self, task: Task) -> Future[TaskResult]: ...
    def submit_batch(self, tasks: List[Task]) -> None: ...   # parallel
    def on_result(self, task, result) -> List[Task]:         # spawns follow-on tasks
        ...
```

The executor uses a thread pool for parallel tasks and a dependency queue for serialized ones. Each task result can spawn new tasks — e.g., `ResolveImports` spawns `BuildCallGraph`, which spawns `ClassifyFunctions`, which spawns `MatchSignatures` and `InferTypes` in parallel before any `AnalyzeFunction` tasks begin.

#### Planner Output: Task DAG

```
Goal: "Analyze binary for malware behavior"
  │
  ├── ResolveImports
  │     └── BuildCallGraph
  │           ├── ClassifyFunctions
  │           │     └── MatchSignatures ────────────────┐
  │           │                                         │
  │           └── InferTypes (from imports + known fns) │
  │                 │                                   │
  │                 ▼                                   ▼
  │           AnalyzeFunction (leaf fns first, BFS up call graph)
  │                 │
  │                 ▼
  │           PropagateNames → re-dirty callers → AnalyzeFunction (callers)
  │                 │
  │                 ▼
  │           FormHypothesis (per discovered component)
  │                 │
  │                 ├── TestHypothesis (network comms?)
  │                 ├── TestHypothesis (persistence mechanism?)
  │                 └── TestHypothesis (crypto routines?)
  │                       │
  │                       ▼
  │                 SynthesizeComponent
  │                       │
  │                       ▼
  │                 GlobalSynthesis
  │                       │
  │                       ▼
  └───────────────── GenerateReport
```

---

### 3. Program Analyzer

Runs before the LLM touches anything. The analyzer populates the KnowledgeGraph with high-confidence structural facts so the LLM reasons over interpreted results, not raw decompiler bytes.

#### Passes (in execution order)

**Import Resolution**
- Match imported symbols against curated databases (libc, Windows API, POSIX, OpenSSL, libcurl, zlib, etc.)
- Assign category tags: `network`, `crypto`, `filesystem`, `process`, `memory`, `ui`
- Confidence: 1.0 for exact name matches

**FLIRT / Signature Matching**
- Match function bytes against known standard library and crypto function signatures
- Auto-resolve and skip matched functions from LLM analysis
- Sources: IDA FLIRT sigs, Ghidra FID databases, custom JSON pattern files

**Call Graph Construction + Type Inference**
- Propagate known types from resolved imports through the call graph
- If `malloc` returns `void*` and the return value is cast to `T*`, infer T at the call site
- If a struct is passed to multiple known functions, infer field layout from usage

**String Cross-Reference Analysis**
- Cluster strings by content type: URLs, registry keys, file paths, error messages, format strings, UUIDs
- Associate each string cluster with the functions that reference it
- These clusters become evidence for component hypotheses

**Control Flow Analysis**
- Identify obfuscation patterns structurally: dispatcher blocks (CFF), always-taken/never-taken branches (opaque predicates), dead code islands, MBA in expressions
- Mark functions as `obfuscated: true` with specific pattern annotations — these go to the deobfuscation pipeline, not straight to LLM

**Component Clustering**
- Use call graph connectivity (strongly connected components + betweenness centrality) to identify functional clusters
- Each cluster becomes a `ComponentNode` candidate
- Import tags and string clusters augment the clustering signal

All passes write `Fact` objects to the KnowledgeGraph. By the time the LLM sees a function, it already has: its import-derived call semantics, its type-inferred parameters, its string cluster associations, its component membership, and any obfuscation flags.

---

### 4. LLM Reasoner

Interprets what static analysis cannot resolve. Operates on structured `AnalysisRequest` objects, not raw decompiler output.

#### Analysis Request Format

```python
@dataclass
class AnalysisRequest:
    function: FunctionNode          # address, current name, size
    decompilation: str              # still included, but as one of many inputs
    known_callees: List[FunctionNode]  # already-named by this point (BFS order)
    type_inferences: List[Fact]     # from PropagateNames pass
    string_clusters: List[StringCluster]  # categorized, not raw
    component_hypothesis: Optional[str]   # "probably network I/O layer"
    import_context: List[ImportNode]      # relevant resolved imports
    obfuscation_notes: List[str]          # from CFG analysis
```

The LLM's job is naming + typing given already-structured evidence, not free-form interpretation of disassembly.

#### Response Format (structured, not prose)

```python
@dataclass
class AnalysisResponse:
    name: str
    confidence: float
    prototype: str
    params: List[ParamInfo]
    comment: str                  # one line max
    struct_proposals: List[StructProposal]
    evidence_summary: str         # why this name was chosen
```

Structured output forces the model to be explicit about confidence and evidence, which feeds back into the KnowledgeGraph rather than being lost as narrative text.

#### Tiered Model Routing

| Task | Model | Reason |
|------|-------|--------|
| Function classification (size, lang) | Haiku | Cheap, structured |
| Single function analysis | Sonnet | Good reasoning, cost-effective |
| Component synthesis | Sonnet | Needs cross-function context |
| Deobfuscation planning | Sonnet | Requires IL reasoning |
| Global synthesis + report | Opus | Full binary context, high stakes |
| Hypothesis formation/testing | Sonnet | Multi-step reasoning |

The router selects model based on task type. Token budget is tracked per model; if a session approaches a cost ceiling, it downgrades gracefully.

#### Prompt Caching

For Anthropic: cache the system prompt, the binary context block, and the serialized KnowledgeGraph summary (top 200 nodes by centrality). These are stable across turns and amortize the 200K token cost of full-binary context.

---

### 5. Hypothesis Engine

A first-class subsystem — not a feature bolted onto a knowledge base. The engine maintains open hypotheses, drives evidence collection, and resolves claims.

```python
@dataclass
class Hypothesis:
    id: str
    claim: str                        # "sub_401a30 is an HTTP request parser"
    confidence: float                 # updated as evidence accumulates
    status: Literal["open", "confirmed", "refuted", "deferred"]
    evidence_for: List[Evidence]
    evidence_against: List[Evidence]
    verification_tasks: List[Task]    # tasks the planner should run to test this
```

#### Hypothesis Lifecycle

1. **Formation** — LLM proposes hypothesis during component synthesis or when a string cluster is anomalous
2. **Verification task generation** — Engine generates targeted tool calls to test the claim (check string refs, look for known HTTP header patterns, inspect call graph neighbors)
3. **Evidence accumulation** — Each verification task returns evidence that updates confidence
4. **Resolution** — Above 0.85 confidence → confirmed, factored into KnowledgeGraph; below 0.15 → refuted, noted; else → deferred for analyst review
5. **Propagation** — Confirmed hypotheses update affected FunctionNodes and ComponentNodes, triggering dirty-marking of dependent facts

The analyst can inspect the evidence chain for any claim: "Why does the agent think this is a TLS handshake function?" → see the evidence list with confidence weights.

---

### 6. Deobfuscation Pipeline

Runs as a set of specialized tasks for functions flagged by the Program Analyzer. Each pattern has its own resolution strategy.

```
Detected pattern → select strategy → apply → re-analyze → verify
```

| Pattern | Strategy |
|---------|----------|
| Control flow flattening | Extract CFG → identify dispatcher variable → trace state transitions → reconstruct original CFG using IL write primitives |
| Opaque predicates | Z3: model branch condition as SMT constraint → if always-true/always-false, nop dead branch |
| MBA expressions | Z3: model expression semantically → simplify to canonical form → replace in IL |
| String encryption | Taint decryption key from data section → symbolic execute decrypt routine → extract plaintext → annotate |
| Indirect calls via dispatch table | Resolve dispatch table statically → concretize call targets → update call graph |
| VM protection | Flag entry/exit, annotate boundary functions — don't attempt automated deobfuscation |

Deobfuscation tasks write their patches as `PatchRecord` objects with full undo support. All patches are staged (in-memory only) until the analyst approves the save gate.

---

### 7. Tool Gateway

All disassembler interactions go through the Tool Gateway. Tools are defined with a `@tool` decorator; the gateway handles execution, mutation tracking, undo, approval gates, and timeout.

```python
@tool(category="decompiler", readonly=True)
def decompile_function(address: Annotated[int, "Function start address"]) -> str: ...

@tool(category="annotations", mutating=True)
def rename_function(address: Annotated[int, "Function address"], name: Annotated[str, "New name"]) -> None: ...

@tool(category="patching", mutating=True, requires_approval=True)
def write_bytes(address: Annotated[int, "Target address"], hex_bytes: Annotated[str, "Bytes as hex string"]) -> None: ...
```

`mutating=True` — captures pre-state, creates `MutationRecord`, enables undo.  
`requires_approval=True` — blocks until analyst confirms in UI or CLI.

Mutations are logged in `SessionState.mutation_log`. `/undo N` replays reverse operations from the tail of the log.

#### Tool Categories

| Category | Tools |
|----------|-------|
| Navigation | `get_cursor`, `jump_to`, `list_segments` |
| Functions | `list_functions`, `get_function_info`, `search_functions` |
| Decompiler | `decompile_function`, `redecompile` |
| Disassembly | `read_disassembly` |
| Xrefs | `xrefs_to`, `xrefs_from` |
| Strings | `list_strings`, `search_strings` |
| Database | `list_imports`, `list_exports`, `read_bytes` |
| Annotations | `rename_function`, `set_comment`, `set_type`, `rename_variable` |
| Types | `create_struct`, `modify_struct`, `set_prototype` |
| IL | `get_cfg`, `get_il`, `il_replace_expr`, `il_set_condition`, `nop_instructions` |
| Symbolic | `solve_constraint`, `find_reaching_values`, `taint_from` |
| Patching | `write_bytes`, `patch_branch` (approval-gated) |
| Scripting | `execute_script` (approval-gated, not in autonomous mode) |

---

### 8. Session Manager

Unified state across both batch and interactive modes. A session can transition between modes mid-run — the analyst can interrupt an autonomous pipeline run, ask a question, redirect the goal, and let it continue.

```python
@dataclass
class Session:
    id: str
    goal: str
    mode: Literal["autonomous", "interactive", "paused"]
    task_graph: TaskGraph                # planner output, mutable
    knowledge_graph: KnowledgeGraph      # live binary model
    mutation_log: List[MutationRecord]
    conversation: List[Message]          # for interactive mode
    context_window: ContextWindowManager
    cost_tracker: CostTracker
    binary_path: str
    host: HostBridge
```

**Mode transitions:**
- `autonomous → interactive`: Analyst types a message mid-run. Engine pauses task execution, enters interactive turn, then resumes autonomous tasks.
- `interactive → autonomous`: Analyst issues `/run` or confirms a plan. Engine executes remaining task graph.
- `paused`: Task graph is frozen; analyst is reviewing a save gate or hypothesis approval.

Sessions are serialized to disk after each task and restored when the binary is reopened. The full task graph, knowledge graph, and conversation are preserved.

#### Context Window Management

The LLM context window contains:
1. System prompt (stable — cached)
2. Binary context block: top-N functions by centrality, component summaries (stable — cached)
3. Current task context: relevant facts from knowledge graph for this task only
4. Recent conversation / tool results

When the window exceeds 80% capacity, the current task context is compacted. The binary context block and system prompt are never compacted — they are cached and re-used.

---

### 9. Host Bridge

Disassembler-agnostic API. Tools call Host Bridge methods; the bridge handles thread marshalling, API differences, and capability reporting.

```python
class HostBridge(ABC):
    @property
    def capabilities(self) -> Capabilities: ...   # has_il, has_decompiler, etc.

    def list_functions(self) -> List[FunctionInfo]: ...
    def decompile(self, address: int) -> str: ...
    def get_cfg(self, address: int) -> CFGraph: ...
    def rename_function(self, address: int, name: str) -> None: ...
    def write_bytes(self, address: int, data: bytes) -> None: ...
    def read_bytes(self, address: int, n: int) -> bytes: ...
    # ... ~40 methods
```

| Host | Notes |
|------|-------|
| `GhidraHost` | PyGhidra + JPype, in-process. Used for CLI/pipeline mode. |
| `IDAHost` | `@idasync` marshals all calls to IDA's main thread. IDA Pro 9.0+. |
| `BinaryNinjaHost` | Thread-safe BN API. Full IL primitive support (MLIL/HLIL). |

The Host Bridge is injected at startup. The rest of the engine never imports disassembler APIs directly.

---

### 10. Interface Layer

#### CLI

```bash
# Autonomous analysis
re analyze ./binary --goal "full symbol recovery"
re analyze ./binary --goal "find vulnerability" --budget 5.00

# Interactive chat over a binary (no disassembler required)
re chat ./binary

# One-off queries
re ask ./binary "what does the function at 0x401a30 do?"

# Eval against ground truth
re eval ./analysis.json ./source.c
```

#### Disassembler Plugin

A Qt panel shared across IDA and BN (different entry points, same panel code).

```
┌────────────────────────────────────────────────────────┐
│  [ Goal: __________________ ]  [Run]  [Stop]  [Export] │
├───────────────────────────────┬────────────────────────┤
│                               │                        │
│   Chat / Task Feed            │  Knowledge Graph View  │
│                               │  (component tree,      │
│   Shows:                      │   hypothesis list,     │
│   · Task completions          │   confidence scores)   │
│   · LLM reasoning steps       │                        │
│   · Hypothesis updates        │                        │
│   · Analyst messages          │                        │
│                               │                        │
├───────────────────────────────┴────────────────────────┤
│  [ Input / Question ]                      [Send]       │
├────────────────────────────────────────────────────────┤
│  Context: 34K / 128K tokens · $0.12 · 3 mutations      │
└────────────────────────────────────────────────────────┘
```

The right panel is a live view of the KnowledgeGraph — not a chat transcript. Analysts can click into a component to see its member functions, hypotheses, and evidence chains. This is the key UX innovation: the graph is the output, not the conversation.

#### MCP Server

Expose the knowledge graph and analysis capabilities as an MCP server. Other agents (or Claude Code) can query the binary model, request analysis of specific functions, or read the current hypothesis list.

---

## Data Flow: Full Autonomous Run

```
re analyze ./malware.exe --goal "identify persistence and C2 mechanisms"
  │
  ├─ Session.new(goal, binary)
  ├─ GhidraHost.load(binary)
  │
  ├─ Planner.decompose(goal) → TaskGraph
  │
  ├─ TaskExecutor.run(TaskGraph):
  │    ├─ ResolveImports → 47 imports resolved, 12 tagged [network], 8 [crypto]
  │    ├─ BuildCallGraph → 312 functions, 1,847 call edges
  │    ├─ MatchSignatures → 89 functions auto-resolved (libc, OpenSSL)
  │    ├─ ClassifyFunctions → 223 remaining: 40 trivial, 110 small, 58 medium, 15 large
  │    ├─ InferTypes → 34 type proposals from import context
  │    ├─ ComponentClustering → 7 component candidates identified
  │    │
  │    ├─ [parallel] AnalyzeFunction × 40 trivial  (Haiku, ~$0.01)
  │    ├─ [parallel] AnalyzeFunction × 110 small   (Sonnet, ~$0.40)
  │    ├─ [serial BFS] AnalyzeFunction × 58 medium (Sonnet, ~$0.80)
  │    ├─ [serial BFS] AnalyzeFunction × 15 large  (Sonnet, ~$0.30)
  │    │       (3 flagged obfuscated → DeobfuscateFunction tasks spawned)
  │    │
  │    ├─ PropagateNames → 89 callers dirty-marked, re-analyzed with updated context
  │    │
  │    ├─ FormHypothesis × 7 (one per component) (Sonnet)
  │    ├─ TestHypothesis × 14 (2 per component) (mixed: static + Sonnet)
  │    │
  │    ├─ SynthesizeComponent × 7 (Sonnet)
  │    ├─ GlobalSynthesis (Opus)
  │    │
  │    └─ GenerateReport (Opus)
  │
  ├─ Export: analysis.json + database writeback
  └─ Summary: 312 functions analyzed, 94% named, $2.87, 11 minutes
```

---

## Analysis Flow: Interactive / Analyst-Driven

```
Analyst: "What is sub_401a30?"
  │
  ├─ Planner: not a full-binary goal — emit single AnalyzeFunction task
  ├─ ProgramAnalyzer.analyze_single(0x401a30):
  │    · 4 string refs found (HTTP status strings)
  │    · 3 resolved callees: recv, malloc, memcpy
  │    · type inference: first arg likely socket_t
  │    · no obfuscation detected
  │
  ├─ LLMReasoner.analyze(AnalysisRequest):
  │    · receives structured facts, not raw pseudocode
  │    · returns: name="parse_http_response", confidence=0.91
  │
  ├─ KnowledgeGraph.update(0x401a30, result)
  ├─ PropagateNames → 2 callers marked dirty
  │
  └─ Response to analyst: "parse_http_response (0.91) — HTTP status strings at 0x402030,
                           0x402045; calls recv→malloc→memcpy; first arg inferred socket_t."

Analyst: "Rename it and add a comment"
  │
  ├─ ToolGateway.rename_function(0x401a30, "parse_http_response")
  │    · MutationRecord appended (reversible)
  ├─ ToolGateway.set_comment(0x401a30, "Parses HTTP response from socket into heap buffer")
  │    · MutationRecord appended (reversible)
  └─ KnowledgeGraph.update(source=ANALYST, confidence=1.0)  ← analyst overrides LLM
```

---

## Key Design Decisions

**Static analysis before LLM.** The expensive part of both Kong and Rikugan is LLM calls on raw decompiler output. Doing import resolution, type inference, and pattern matching first means the LLM gets structured evidence, not noise. It names faster, more accurately, and for less money.

**Knowledge graph over flat memory.** A flat Markdown file (Rikugan) or per-function JSON (Kong) can't answer "which functions touch the network?" or "what called into this struct?". A live graph enables the planner to make directed decisions, the hypothesis engine to query for evidence, and the analyst to explore the model visually.

**Hypothesis engine as a first-class subsystem.** Neither existing tool tracks claims with explicit evidence and confidence. Without this, the analyst has no way to know why the agent concluded something, or how confident to be. The hypothesis engine makes reasoning transparent and auditable.

**Goal-driven task planning over fixed phases or reactive loop.** Kong's fixed 5-phase pipeline can't handle "find the vulnerability" — it doesn't know what to synthesize toward. Rikugan's reactive loop can, but requires constant analyst steering. Goal decomposition into a task DAG handles both autonomously and interactively.

**Tiered model routing by task type.** Classification and trivial function analysis don't need Opus. Reserving expensive models for synthesis and complex reasoning cuts cost by 3-5x without quality loss.

**Incremental dirty tracking.** When the analyst corrects a name or a new function is resolved, the downstream impact is scoped. Only dirty nodes get re-analyzed. Neither existing tool supports this — they require a full re-run or manual steering.

**Unified session across modes.** The analyst can interrupt a running pipeline, ask a question, redirect the goal, and resume. This is architecturally simpler than maintaining two separate codebases (Kong for batch, Rikugan for interactive) and means interactive mode benefits from all the static analysis infrastructure.

---

## Technology Stack

| Concern | Choice |
|---------|--------|
| Language | Python 3.11+ |
| Package manager | uv |
| Graph store | NetworkX (in-process) + optional Neo4j for large binaries |
| Binary analysis (pipeline) | Ghidra via PyGhidra + JPype |
| Binary analysis (plugin) | IDA Pro 9.0+ / Binary Ninja |
| LLM | Anthropic SDK (Claude) — Haiku / Sonnet / Opus routing |
| LLM fallback | OpenAI SDK, Ollama |
| Symbolic analysis | Z3 |
| CLI | Click |
| TUI | Textual |
| Plugin UI | Qt via host PySide6 bindings |
| Serialization | msgpack (graph), JSON (analysis output) |
| Testing | pytest |
| Eval | Custom symbol_accuracy + type_accuracy harness |

---

## Project Layout

```
ai_re/
├── core/
│   ├── knowledge_graph.py     # KnowledgeGraph, FunctionNode, HypothesisNode, Fact
│   ├── hypothesis.py          # HypothesisEngine, Evidence, lifecycle
│   ├── session.py             # Session, SessionManager, mode transitions
│   └── events.py              # EventBus, AnalysisEvent types
├── planning/
│   ├── planner.py             # GoalPlanner, TaskGraph decomposition
│   ├── executor.py            # TaskExecutor, dependency queue, thread pool
│   └── tasks.py               # Task dataclasses, TaskResult
├── analysis/
│   ├── imports.py             # Import resolution, category tagging
│   ├── signatures.py          # FLIRT/FID matching, signature DBs
│   ├── types.py               # Type inference, propagation
│   ├── cfg.py                 # CFG analysis, obfuscation detection
│   ├── strings.py             # String cross-reference clustering
│   ├── components.py          # Call graph clustering, ComponentNode formation
│   └── normalizer.py          # Decompiler output normalization
├── deobfuscation/
│   ├── dispatcher.py          # CFF detection + CFG reconstruction
│   ├── predicates.py          # Opaque predicate solving via Z3
│   ├── mba.py                 # MBA simplification
│   └── strings.py             # Encrypted string recovery
├── llm/
│   ├── reasoner.py            # LLMReasoner, AnalysisRequest/Response
│   ├── router.py              # Tiered model selection
│   ├── anthropic_client.py    # Streaming, prompt caching, retry
│   ├── openai_client.py
│   ├── base.py                # LLMClient ABC, StreamChunk
│   └── usage.py               # CostTracker, TokenUsage
├── tools/
│   ├── base.py                # @tool decorator, ToolDefinition
│   ├── gateway.py             # ToolGateway, mutation log, approval gates
│   ├── navigation.py
│   ├── functions.py
│   ├── decompiler.py
│   ├── xrefs.py
│   ├── strings.py
│   ├── annotations.py
│   ├── types.py
│   ├── il.py
│   ├── symbolic.py
│   └── patching.py
├── host/
│   ├── base.py                # HostBridge ABC, Capabilities
│   ├── ghidra.py
│   ├── ida.py
│   └── binja.py
├── interactive/
│   ├── loop.py                # Generator-based interactive turn cycle
│   ├── turn.py                # TurnEvent, TurnEventType
│   └── context_window.py      # ContextWindowManager
├── signatures/
│   ├── stdlib.json
│   ├── crypto.json
│   └── protocols.json         # HTTP, TLS, SMB pattern markers
├── evals/
│   ├── harness.py
│   └── metrics.py
├── ui/
│   ├── tui/app.py             # Textual (CLI progress)
│   └── plugin/
│       ├── panel.py           # Qt panel (IDA + BN)
│       ├── chat_view.py
│       ├── graph_view.py      # Knowledge graph tree panel
│       └── mutation_panel.py
├── config.py
├── __main__.py                # CLI (Click)
└── tests/
```

---

## Milestones

### Phase 1 — Foundation
- [ ] HostBridge + GhidraHost
- [ ] Tool Gateway (30 core tools, mutation log, undo)
- [ ] KnowledgeGraph with Fact model
- [ ] ProgramAnalyzer: import resolution, signature matching, call graph
- [ ] LLMReasoner with structured AnalysisRequest/Response
- [ ] Tiered model routing (Haiku / Sonnet)
- [ ] CLI: `re analyze`, `re chat`
- [ ] Eval harness

### Phase 2 — Planning + Hypotheses
- [ ] GoalPlanner + TaskExecutor
- [ ] HypothesisEngine (formation, verification, resolution)
- [ ] Component clustering
- [ ] Type inference + name propagation with dirty tracking
- [ ] GlobalSynthesis with Opus
- [ ] Session persistence + mode switching

### Phase 3 — Deobfuscation + Plugins
- [ ] CFG-based CFF detection + reconstruction
- [ ] Opaque predicate solver (Z3)
- [ ] IDAHost + BinaryNinjaHost
- [ ] Plugin UI (Qt panel with graph view)
- [ ] Exploration mode for analyst-directed binary modification
- [ ] Save gate + patch rollback

### Phase 4 — Scale + Ecosystem
- [ ] MCP server exposure
- [ ] Neo4j backend for large binaries (>10K functions)
- [ ] MBA simplification
- [ ] Parallel subagent analysis (one subagent per component)
- [ ] CI eval benchmarks (XZ backdoor, CVE case studies)
