# dispatch

Event-driven incident orchestration for the 5G_PCAP stack: an Alarm event
(human-raised, or synthesized from KPI degradation) flows through the
Dispatcher — an Incident Manager agent that fans out to three specialist
evidence agents (PCAP, Log, KPI), links their findings into a correlation
graph, runs a root-cause investigation, proposes a remediation from a fixed
action vocabulary, and gates execution on Human approval. Invoked
per-event; not a live monitor (v1). Sandbox-scoped: every command it can
execute is safe and reversible inside the Open5GS+UERANSIM lab.
Architecture rationale:
[`docs/adr/0001-incident-orchestration.md`](./docs/adr/0001-incident-orchestration.md);
remediation safety:
[`docs/adr/0002-remediation-proposal-and-executor.md`](./docs/adr/0002-remediation-proposal-and-executor.md).

## Language

**Dispatcher**:
The dispatch context's central agent — the diagram's Incident Manager.
Receives one Alarm event, fans out to the specialist agents, correlates
their Evidence items, runs the root-cause investigation, renders the
Remediation proposal, and halts for Human approval. Also the package
name.
_Avoid_: orchestrator, manager agent, controller

**Alarm event**:
The input: a JSON event file `{incident_id, detected_at, source:
kpi|alarm|human, procedure?, time_window, description, kpi?, captures?}`.
Emitted by a human, or synthesized deterministically by the
KPI-degradation comparator (`dispatch detect-kpi`) comparing 5gcap's
computed KPIs against the Golden baseline. Delivered as a file to a
per-invocation `dispatch handle`; no daemon, no webhook (v1).
_Avoid_: alert, trigger, ticket

**Specialist agent**:
One of the three evidence-gathering agents the Dispatcher fans out to:
the PCAP Agent (a `triage analyze` run over the event's captures), the
Log Agent (LLM extraction over docker stdout logs in the event's time
window, with a code-enforced log-grounding check), or the KPI Agent
(deterministic 5gcap KPI computation plus deviation from the Golden
baseline). Each emits Evidence items.
_Avoid_: worker, sub-agent, tool

**Evidence item**:
One structured fact from any source — the shared currency the
correlation graph is built from: `{source: pcap|log|kpi, kind, ts,
entry, cause?, endpoints?, keys: {supi?, teid?, nf?, flow_id?},
citation}`. The `citation` names the item's exact origin (decode
handle, log line, KPI name) and is the honesty hook: grounding is
checked in code per source, never trusted to the LLM.
_Avoid_: proof, data, finding

**Correlation graph**:
The deterministic linking of Evidence items: items sharing a key (SUPI,
TEID, NF name, flow id) within the event's time window are linked;
ambiguous keys link nothing; the window alone never links — it is
candidate scope, not a predicate. Built in code; the LLM reads it,
never builds it.
_Avoid_: fusion, merge, synthesis

**Root-cause investigation**:
The Dispatcher-layer search over the correlation graph, reusing
triage's LATS machinery (Tree, signatures, gpt-oss:120b via Groq) as a
library, with the grounding discipline extended to a multi-source
inventory. Produces the root-cause narrative.
_Avoid_: diagnosis, analysis

**Remediation proposal**:
The Dispatcher's output for Human approval: LLM-drafted prose
justification plus a selection from the fixed action vocabulary
(`restart_nf`, `revert_config`, `reseed_subscriber`, `rerun_capture`,
`observe_only`); the exact commands come from deterministic templates,
never free-form LLM text. Nothing executes without approval.
_Avoid_: fix, action plan

**Human approval**:
The gate between proposal and action. The graph checkpoints to sqlite
at the proposal step and exits; the human reviews the proposal file
and resumes with `dispatch approve <incident_id>` (or `reject`),
reloading the checkpoint — LangGraph's pause across process
boundaries, keeping the no-daemon posture.
_Avoid_: sign-off, confirmation

**Incident Record**:
The deterministic Markdown artifact per incident: event, correlation
graph, root cause, proposal, approval status, execution log. The only
LLM prose in it is the root-cause narrative and the proposal
justification (ADR-0004's principle extended). Stored under
`dispatch/records/`.
_Avoid_: report, writeup, dossier

**Golden baseline**:
The committed KPIs of the sandbox golden triple — the comparator's
reference for "degradation". Generated once by 5gcap from the golden
fixtures, byte-stable, committed.
_Avoid_: threshold, norm

**Executor**:
The deterministic runner that applies an approved proposal's commands —
vocabulary-only, sandbox paths/containers only, dry-run by default,
commands appended to the Incident Record.
_Avoid_: deployer, runner

**Outcome**:
The operator's verified verdict on an executed remediation — `resolved`
or `unresolved` — recorded when the incident is closed. The only
post-execution truth the system may learn from.
_Avoid_: result, status, feedback

**Episode**:
A decided incident: its signature (procedure, scenario, evidence keys),
decision, executed action, and — once the operator closes it — its
Outcome. The unit of dispatch's episodic memory, consulted by later
investigations of the same signature.
_Avoid_: log entry, case history, ticket

**Runbook**:
A documented, reusable remediation for a failure signature: structured
symptoms and ordered steps that resolve to exactly one action from the
vocabulary. The unit of procedural memory. Seeded by operators, and
only ever changed through the Learning loop — a Runbook is proposed by
the system, never self-applied.
_Avoid_: playbook, SOP, recipe

**Learning loop**:
The CoALA feedback path: a resolved Episode drafts a Runbook proposal
for an operator to review and promote. Human-gated throughout —
nothing the loop learns takes effect without a human moving it into
place.
_Avoid_: auto-learning, self-improvement
