# NetCortex

An Agentic AI Platform for Autonomous Network Operations

5G control-plane capture analysis: decode NGAP/NAS (N2), PFCP (N4), and SBI
(HTTP/2) captures, map per-UE flows, compute KPIs, triage failed
procedures with an LLM agent, and run incidents through a human-gated
remediation pipeline.

## The dispatch pipeline

![Dispatch pipeline — raise or detect, handle, human-gated execution, close + learn](dispatch/docs/diagrams/pipeline.png)

One incident, end to end: an Alarm event (human-raised or synthesized
from KPI degradation) fans out to three specialist evidence agents,
their findings are correlated, a LATS root-cause search runs, and a
remediation proposal from a fixed five-action vocabulary waits at the
Human approval gate — with the Outcome feeding a gated learning loop.
The committed end-to-end
[`sample Incident Record`](dispatch/docs/sample-incident-record.md) shows
a real `n4_upf_timeout` run: detected from KPI degradation, investigated
by the live specialists, left **pending** at the gate. The diagram's
source of truth is
[`dispatch/docs/diagrams/pipeline.json`](dispatch/docs/diagrams/pipeline.json).

## Layout

- [`5gcap/`](5gcap/) — the analyzer itself (`5gcap analyze <file.pcap>`),
  one binary ladder N2 → N4 → SBI; given all three captures, one merged
  JSON export correlated by strict key equality (ADR-0007). See
  [`5gcap/README.md`](5gcap/README.md) for usage and v1 scope.
- [`triage/`](triage/) — LLM-agent root-cause hypothesis generation over
  5gcap's decode output (LATS search, episodic memory, 3GPP spec graph; on
  the merged export, joined SBI/N4 Incidents carry their flow id), a
  deterministic post-incident report writer, and an offline eval harness
  scored against labeled sandbox fixtures. A sample post-incident report
  from a live run is in
  [`triage/examples/`](triage/examples/auth_failure-report.md). See
  [`triage/README.md`](triage/README.md).
- [`sandbox/`](sandbox/) — local Open5GS + UERANSIM lab that generates real
  captures for `5gcap` and labeled failure-injection scenario fixtures
  (`./capture.sh --scenario <name>`) for triage's evals. See
  [`sandbox/README.md`](sandbox/README.md).
- [`dispatch/`](dispatch/) — event-driven incident orchestration over the
  stack: a KPI-degradation detector or a human raises an Alarm event,
  PCAP/Log/KPI specialist agents ground evidence against the decode,
  core logs and the Golden baseline, a root-cause search correlates it,
  and a remediation proposal from a fixed five-action vocabulary waits
  at a Human approval gate. A real end-to-end
  [`sample Incident Record`](dispatch/docs/sample-incident-record.md) is
  committed. See [`dispatch/README.md`](dispatch/README.md).
- [`CONTEXT.md`](CONTEXT.md) — 5gcap domain glossary (Capture, Flow,
  Procedure, KPI, Partial Flow); [`triage/CONTEXT.md`](triage/CONTEXT.md) —
  triage domain glossary; [`dispatch/CONTEXT.md`](dispatch/CONTEXT.md) —
  dispatch domain glossary. [`CONTEXT-MAP.md`](CONTEXT-MAP.md) maps the
  three contexts and their relationships.
- [`docs/adr/`](docs/adr/) — architecture decision records.
- Diagrams — [`docs/diagrams/`](docs/diagrams/) holds the 5gcap pipeline
  diagram from the Medium article (fireworks-tech-graph IR + rendered
  SVG + PNG, style 2 Dark Terminal; the regeneration recipe, including
  the no-system-fonts PNG trap, is in its
  [`README`](docs/diagrams/README.md));
  [`dispatch/docs/diagrams/`](dispatch/docs/diagrams/) holds the
  dispatch pipeline's set — the same IR + SVG + PNG trio plus
  LangGraph's own mermaid view of the compiled graph for comparison —
  with the same recipe in its
  [`README`](dispatch/docs/diagrams/README.md); and
  [`triage/docs/diagrams/`](triage/docs/diagrams/) holds the triage
  invocation-flow diagram (IR + SVG).

## Roadmap

Planned as sibling projects on this platform: a **Change Impact Agent**, a
**Cross-Domain Incident Correlation** project, and a **Digital Twin** —
each will land as its own top-level directory alongside `5gcap/`,
`triage/`, and `dispatch/`.

## Development

```
cd 5gcap
uv sync
uv run pytest
```

```
cd triage
uv sync
uv run pytest
```

```
cd dispatch
uv sync
uv run pytest
```
