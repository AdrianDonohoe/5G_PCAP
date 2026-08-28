# Event-driven incident orchestration (the dispatch context)

The stack's next evolution is an incident-response layer over the existing
decode (`5gcap`) and analysis (`triage`) contexts: an Alarm event fans out
to three specialist evidence agents (PCAP, Log, KPI), their findings are
correlated deterministically, a root-cause investigation runs over the
correlated evidence, a remediation is proposed from a fixed vocabulary, and
execution gates on human approval. This records the shape decisions for
that layer, worked out as a design tree with the stack's existing ADRs.

## Status

accepted

## Considered Options

**Orchestration framework** — LangGraph for the Incident Manager vs. another
hand-rolled loop vs. a fixed pipeline. Chose LangGraph, and only for the
Manager: the conditions that made triage's hand-rolled Tree right (one-shot,
bounded, stateless, offline-testable — see triage's ADR-0001 and the
search.py module docstring) are exactly the conditions that change at this
layer — an incident lifecycle with a human-approval pause, checkpoint/resume
across process boundaries, and fan-out joins across agents. DSPy remains the
LM abstraction underneath; triage's Tree stays untouched for per-incident
search.

**Trigger model** — a live monitor vs. event-driven invocation. Chose
event-driven v1: an Alarm event arrives as a JSON file and the Dispatcher
runs per-invocation; no daemon, no webhook. The sandbox has no alarm source
(its Open5GS configs were deliberately trimmed of metrics), and Open5GS's
official metrics surface is too shallow for the triggers anyway (only
AMF/MME/SMF export metrics, and only process-level gauges plus `ues_active`
— no procedure-level failures or latencies). The KPI-degradation half of the
trigger is instead synthesized deterministically: `dispatch detect-kpi`
compares `5gcap`'s own computed KPIs (which are richer than anything
Prometheus exposes) against a committed golden baseline. Prometheus and a
third-party NMS were both examined and deferred: the former is the roadmap
for a future live-monitoring branch, the latter is an operator's dashboard
with no outbound event channel and the wrong deployment shape for the lab.

**Human approval without a daemon** — a LangGraph interrupt normally
implies a long-lived process waiting to resume, which the per-invocation
posture forbids. Chose cross-invocation resume: the graph checkpoints to
sqlite at the proposal step and exits; `dispatch approve <incident_id>` (or
`reject`) reloads the checkpoint and resumes the graph. State (checkpoints,
records, correlation graphs) lives in a gitignored sqlite store.

**Root-cause step** — a second LATS-style search over a multi-source
inventory at the Dispatcher layer vs. extending triage's Action space with
log/KPI tools. Chose the Dispatcher-layer search, importing triage's Tree
and signatures as a library: triage's completeness bar grounds citations in
the decode, which log lines cannot satisfy without reworking the invariant,
and multi-source fusion belongs where the sources actually meet. Dispatch
is therefore the only context that depends on triage's Python API;
`5gcap` is consumed by subprocess only (its reproducibility guarantee
stays out of the agent's process), and the PCAP Agent is a `triage
analyze` run over the event's captures.

**Evidence correlation** — deterministic linking vs. LLM-mediated fusion.
Chose deterministic: specialist agents emit structured Evidence items
(`{source, kind, ts, entry, cause?, endpoints?, keys?, citation}`), and a
code step links items that share a key (SUPI, TEID, NF name, flow id)
within the event's time window. The window is candidate scope only, never
a link predicate; ambiguous keys link nothing. The LLM reads the
correlation graph, never builds it — the same never-guess principle as
the decode-layer correlation.

**Grounding, per source** — the triage search's grounding discipline
(ADR-0001's completeness bar) extends to every source: a pcap Evidence item
must match the decode inventory, a log item must cite a line that exists in
the window (code-enforced), a KPI item must name a computed KPI value.
The `citation` field is the honesty hook; grounding is checked in code,
never trusted to the LLM.

## Consequences

- `dispatch/` is a new bounded context with its own glossary
  (`dispatch/CONTEXT.md`) and ADRs; the CONTEXT-MAP records the three
  edges: →5gcap subprocess-only, →triage library edge, →sandbox action
  scope.
- Dependencies: langgraph, langgraph-checkpoint-sqlite, dspy, pydantic,
  plus triage as a path dependency.
- The committed golden baseline (`dispatch/baseline/golden_kpis.json`,
  generated once by 5gcap from the golden triple) makes "KPI degradation"
  computable as deviation-from-golden with no hand-edited thresholds.
- Eval mirrors triage's: offline pytest with stubbed agent outputs
  (Groq-free), fixture-driven deterministic asserts across the nine
  labeled scenarios, and a live `dispatch/evals/` harness with the same
  generator/judge split.
- The first tracer slice is `n4_upf_timeout` — it exercises all three
  agents, the correlation, and the approval path before any generality
  is added.
