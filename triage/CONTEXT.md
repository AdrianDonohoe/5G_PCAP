# triage

LLM-agent root-cause hypothesis generation for failed 5G Registration and PDU
Session Activation Procedures, SBI service transactions, and N4
session-management procedures, built on top of 5gcap's decode output (N2,
N4, SBI planes). Invoked
one-shot: the CLI consumes a single decoded Capture and the agent runs once
per failed Incident within it; not a live/streaming monitor.
Architecture rationale: [`docs/adr/0001-lats-coala-triage-agent.md`](./docs/adr/0001-lats-coala-triage-agent.md).

## Language

**Incident**:
A single failed Procedure (Registration or PDU Session Activation) within one
N2 Flow, a failed SBI service transaction (one HTTP request/response
pair), or an **N4 incident** (below) — either an explicit Reject with a
cause code (or an HTTP status >= 400), or a terminal message that never
arrives (an unanswered SBI request). The unit of work the agent is invoked
on. SBI and N4 Incidents have no Flow of their own; where the decode's
merged export correlates their procedure to an N2 Flow, the Incident
carries that flow's id as `flow_id` — a link that exists or doesn't, never
a guess. An unjoined Incident carries none.
_Avoid_: alert, event, case

**N4 incident**:
A failed session-management PFCP procedure (session establishment /
modification / deletion / report) on the N4 plane — an explicit Reject
carrying a PFCP Cause, or a request never answered by capture end.
Heartbeat, association, and node-report procedures are maintenance traffic:
listable and citable as Evidence, never an Incident.
_Avoid_: PFCP failure, UPF error

**Evidence**:
A concrete fact drawn from 5gcap's decode output — a specific message, IE,
Cause value, or (on the SBI plane) service transaction — that a Hypothesis
cites to support its claim. A Hypothesis with no Evidence is not a valid
Hypothesis. SBI Evidence cites the service name with `cause = None`; the
HTTP status lives in the narrative prose. N4 Evidence cites the PFCP
message name; a cause-bearing response carries the numeric PFCP cause.
_Avoid_: proof, data, context

**Hypothesis**:
The agent's final structured output for an Incident: a root-cause narrative
grounded in at least one piece of Evidence, plus a classified `incident_type`.
Produced once per Incident, after the LATS search concludes.
_Avoid_: diagnosis, answer, result

**incident_type**:
The canonical category a Hypothesis is classified into — a closed set of
ten, one per (Procedure × failure shape) combination: `auth_failure`,
`registration_reject`, `registration_timeout`, `pdu_session_reject_slice`,
`pdu_session_reject_other`, `pdu_session_timeout`,
`pdu_session_rsp_timeout`, `sbi_udm_timeout`,
`sbi_nssf_reject`, `n4_upf_timeout`. Maps one-to-one onto the
sandbox's failure-injection scenario labels, which supply ground truth for
`type_accuracy`. New categories are added only when a real failure shape
doesn't fit any of these, not speculatively: `pdu_session_rsp_timeout`
earned its slot because the merged decode exposes the unanswered
sm-contexts create (SBI timeout joined to the flow), a shape
`pdu_session_timeout`'s invisible create cannot express.
_Avoid_: category, label, class

**Action**:
A single tool call available to the LATS search's execute step:
`inspect_decoded_evidence`, `query_topology`, `query_3gpp_spec`, or
`query_episodic_memory`. The unit LATS's expand step samples from.
_Avoid_: step, tool call, operation

**Trajectory**:
One candidate sequence of (Action, observation) pairs explored during the
LATS search, scored by the evaluate step. The winning Trajectory's final
observation becomes the Hypothesis.
_Avoid_: path, rollout

**Topology**:
The network-element roles (which IP is the AMF/SMF/UPF/gNB) and UE/Flow
relationships for a Capture, inferred purely from message content — no
external inventory or config is assumed.
_Avoid_: inventory, network map

**Episode**:
The record written once, post-hoc, after a Hypothesis is finalized: the
Hypothesis plus the Evidence it cited (not the full Trajectory). The unit
stored in and retrieved from episodic memory.
_Avoid_: dossier, case file, memory entry

**Post-incident report**:
The deterministic Markdown artifact assembled from a saved triage run plus
the decode: the Episode's narrative verbatim, cited evidence re-verified
against the decode, spec-graph context, the flow timeline, capture KPIs,
the search path, and the memory note. The only LLM prose in it is the
Episode's narrative (ADR-0004). Timeline and evidence lines attribute
each message's endpoints (`over N2 from gNB (10.53.0.20) to AMF
(10.53.0.11)`), naming entities only where the plane's own semantics
determine them — N2 NGAP message direction, N4 PFCP request/response
type, SBI service producer; otherwise the endpoints appear as bare
addresses, never guessed.
_Avoid_: writeup, summary, debrief

**type_accuracy**:
Eval-harness metric: exact match between a Hypothesis's `incident_type` and a
sandbox scenario's ground-truth label. Heuristic, not judged.
_Avoid_: classification accuracy

**diagnosis_quality**:
Eval-harness metric: mean of four 0–1 dimension scores (Accuracy, Specificity,
Evidence, Causality) rating a Hypothesis's narrative, produced by an LLM judge
distinct from the model that generated the Hypothesis. Runs only in the
offline eval harness, never during a live invocation.
_Avoid_: quality score, judge score

**Trace**:
The LangSmith record of one root run — a single LATS search invocation (in
dispatch, one pipeline run) — containing nested child runs. Off unless the
tracing gate is on. The dspy callback that feeds it lives in
`triage/tracing.py`; dispatch inherits it.
_Avoid_: log, event stream

**Run**:
One node of a Trace — a search node's phase (`expand`, `execute`,
`evaluate`, `backprop`), a dspy module call, or an LM call — with its
inputs, outputs, and timing. Parent–child structure mirrors the search
tree, not the call stack.
_Avoid_: span, record, entry

**Tracing gate**:
The opt-in condition that arms tracing: `LANGSMITH_TRACING` truthy *and*
`LANGCHAIN_API_KEY` set. With the gate off, no tracer is constructed and no
network is used — ADR-0002's offline posture holds.
_Avoid_: tracing flag, observability switch

**LangSmith project**:
The named bucket a Trace posts to, from the `LANGSMITH_PROJECT`
environment variable (never committed). Triage and dispatch share one
project; runs are tagged by source.
_Avoid_: dashboard, workspace
