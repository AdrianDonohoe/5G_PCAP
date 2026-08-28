# Remediation proposal and executor: fixed vocabulary, human gate

The Dispatcher's final steps turn a root cause into a remediation proposal
and, after human approval, execute it against the sandbox. Putting an LLM
in that path is the riskiest part of the design: a hallucinated command, a
scope escape, or an over-eager action all do real damage in the lab. This
records the guard rails.

## Status

accepted

## Considered Options

**Proposal content** — free-form LLM-generated commands vs. a fixed action
vocabulary with deterministic templates. Chose the fixed vocabulary: the
LLM drafts the prose justification and *selects* from a closed set
(`restart_nf`, `revert_config`, `reseed_subscriber`, `rerun_capture`,
`observe_only`); the exact commands come from deterministic templates
(e.g. `docker compose restart <nf>` in the sandbox core), never from LLM
text. Free-form commands would make the executor's behavior unverifiable
offline and put the repository's public posture at risk.

**Execution trigger** — auto-remediation vs. a human gate. Chose the
human gate: the graph checkpoints at the proposal step and exits; the
human reviews the proposal file and resumes with `dispatch approve` (or
`reject`). Nothing executes without approval. This is also what the
diagram itself specifies (Human Approval / Action).

**Application mode** — execute on approve vs. dry-run by default. Chose
dry-run by default: approval prints the exact commands to the Incident
Record; applying them requires an explicit `--execute`. A mis-click or a
misjudged approval should never be the difference between observing and
mutating the lab.

**Proposal integrity** — trust the proposal file vs. verify against the
checkpoint. Chose verification: the executor runs only commands from the
checkpointed proposal matching the incident's record (hash check), so a
hand-edited proposal file cannot smuggle in an unapproved command.

**Containment** — any container/path vs. sandbox containment. Chose
containment: container names come from a fixed allowlist of the sandbox
core's services, and file paths are restricted to the sandbox tree.
Every command — dry-run or executed — is appended to the Incident
Record.

## Consequences

- The Executor is deterministic and fully testable offline: vocabulary
  enforcement, dry-run behavior, hash verification, and containment are
  plain pytest territory (Groq-free).
- Every action in the vocabulary is safe and reversible inside the
  Open5GS+UERANSIM lab; anything else is out of scope for v1.
- Adding a vocabulary entry is a deliberate design decision (an amendment
  to this ADR), not a runtime addition — the LLM cannot extend its own
  action space.
- The Incident Record's execution log is the audit trail: what was
  proposed, what was approved, what was printed, and what was applied.
