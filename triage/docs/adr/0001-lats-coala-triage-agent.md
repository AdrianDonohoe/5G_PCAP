# LATS-based reasoning with post-hoc CoALA memory for failure triage

We're building an LLM agent that, given a single decoded Capture (invoked
one-shot, not a live monitor), hypothesizes why a Registration or PDU Session
Activation Procedure failed — covering both explicit Reject (with a cause
code) and Partial Flow (timeout, no terminal message at all). `5gcap`'s
decode is deterministic and already computes KPIs; the agent's job starts
where that ends: explaining *why* a specific failure happened, which requires
open-ended investigation, not a fixed computation.

## Status

accepted

## Considered Options

**Orchestration shape** — a fixed pipeline (decode → topology → LATS →
memory-update, each stage handing off to the next) vs. LATS as the central
loop with topology/RAG/episodic-memory as tools its `execute` step calls on
demand (ReAct-style, matching the pattern already in
`raw_graphify/dspy_lats.py`'s RoVer example). Chose the latter: a fixed
pipeline forces topology/spec-lookup/memory-lookup to run whether or not
they're relevant to a given Incident; a single search loop with tools lets
the agent only pay for the investigation it actually needs, and reuses a
reference implementation already in this repo rather than inventing a new
orchestration pattern.

**Where CoALA's memory-update runs** — as another tool inside the search
loop, or once, after the loop concludes. Chose post-hoc: mid-search learning
would let an unfinished, unscored Trajectory pollute memory; CoALA's own
framing treats memory consolidation as reflection on a *concluded* episode,
not a reasoning step.

**Completeness bar** — a Trajectory is `complete` only when its Hypothesis
cites at least one piece of Evidence from `5gcap`'s decode output. Rejected:
accepting any plausible-sounding narrative — this is the single mechanism
that keeps the agent from fabricating causes, and is why LATS (which scores
every Trajectory via its evaluate step) was chosen over a single free-form
LLM call.

**NAS decryption scope** — `CryptoMobile`-based NAS decryption (previously
"planned, not v1" per `docs/adr/0001-scapy-for-packet-parsing.md`) is now in
scope. Without it, most Reject messages' actual cause codes are invisible
(NAS is security-protected after the first exchange), leaving the agent
almost nothing concrete to reason from on the most common failure shape.
Feasible now specifically because sandbox-generated captures use known test
keys; decrypting arbitrary real-world captures with unknown keys remains out
of scope.

**Eval timing** — `diagnosis_quality` (LLM-as-judge) runs only in an offline
eval harness against sandbox-labeled fixtures, never during a live
invocation. Judging every production run would double the LLM cost/latency
of every invocation for a signal that's only needed during development.

## Consequences

- `5gcap`'s `N2Message`/`N4Message` must be extended to carry IP addresses
  (currently ports-only) — `query_topology` has nothing to infer network
  roles from otherwise.
- `sandbox/` must be extended with failure-injection scenarios (e.g. a wrong
  Ki to force an auth reject, an unsupported slice to force a PDU session
  reject), each labeled with a ground-truth `incident_type` — without this,
  `type_accuracy` and `diagnosis_quality` have no fixtures to run against.
- This is a separate bounded context (`triage/`, own `CONTEXT.md`), not a
  module inside `5gcap`: it's non-deterministic, needs an LLM/RAG/memory
  store, and can't offer the reproducibility guarantee `5gcap`'s decode does.
  See `../CONTEXT-MAP.md`.
- The agent's structured output must validate against a Pydantic schema
  (`incident_type` + narrative + cited Evidence) and every tool call must be
  wrapped for exception handling — malformed/adversarial input must degrade
  to an honest "couldn't determine" rather than a crash or a fabricated
  answer, consistent with `5gcap`'s existing lenient-decode philosophy.
- Model and observability stack (`dspy_lats.py`'s Ollama `gpt-oss:120b` +
  MLflow) are not carried over as requirements — only the DSPy/LATS
  structural pattern is. Model/tracing choices are a later, separate
  decision.
