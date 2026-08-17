# triage

LLM-agent root-cause hypothesis generation for failed 5G Registration and PDU
Session Activation Procedures, built on top of 5gcap's decode output. Invoked
one-shot: the CLI consumes a single decoded Capture and the agent runs once
per failed Incident within it; not a live/streaming monitor.
Architecture rationale: [`docs/adr/0001-lats-coala-triage-agent.md`](./docs/adr/0001-lats-coala-triage-agent.md).

## Language

**Incident**:
A single failed Procedure (Registration or PDU Session Activation) within one
Flow — either an explicit Reject with a cause code, or a Partial Flow whose
terminal message never arrives. The unit of work the agent is invoked on.
_Avoid_: alert, event, case

**Evidence**:
A concrete fact drawn from 5gcap's decode output — a specific message, IE, or
Cause value — that a Hypothesis cites to support its claim. A Hypothesis with
no Evidence is not a valid Hypothesis.
_Avoid_: proof, data, context

**Hypothesis**:
The agent's final structured output for an Incident: a root-cause narrative
grounded in at least one piece of Evidence, plus a classified `incident_type`.
Produced once per Incident, after the LATS search concludes.
_Avoid_: diagnosis, answer, result

**incident_type**:
The canonical category a Hypothesis is classified into — a closed set of six,
one per (Procedure × failure shape) combination: `auth_failure`,
`registration_reject`, `registration_timeout`, `pdu_session_reject_slice`,
`pdu_session_reject_other`, `pdu_session_timeout`. Maps one-to-one onto the
sandbox's failure-injection scenario labels, which supply ground truth for
`type_accuracy`. New categories are added only when a real failure shape
doesn't fit any of these six, not speculatively.
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
_Avoid_: path, rollout, run

**Topology**:
The network-element roles (which IP is the AMF/SMF/UPF/gNB) and UE/Flow
relationships for a Capture, inferred purely from message content — no
external inventory or config is assumed.
_Avoid_: inventory, network map

**Episode**:
The record written once, post-hoc, after a Hypothesis is finalized: the
Hypothesis plus the Evidence it cited (not the full Trajectory). The unit
stored in and retrieved from episodic memory.
_Avoid_: incident record, memory entry

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
