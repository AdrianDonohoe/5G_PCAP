# Structured memory and gated learning: episodes, runbooks, and the close loop

Incidents should make the Dispatcher smarter, but a lab orchestrator
cannot let a model write its own playbook — learning that self-applies is
a runaway remediation risk, and retrieval that needs embeddings or API
calls breaks the offline posture (ADR-0002). This records the memory
stage: two structured stores (episodic and procedural), plain-file
lookups, and a feedback loop whose only writer to committed runbooks is
the operator.

## Status

accepted

## Considered Options

**Episodic memory backend** — a vector/embedding store vs. an append-only
local JSONL store with structured lookup. Chose the append-only local
store (`dispatch/state/episodes.jsonl`, beside the checkpointer, triage's
proven MemoryStore pattern — corrupt lines skipped on load). The
structured-lookup argument is triage's, already recorded in
[`../../../triage/docs/adr/0002-triage-v1-implementation-choices.md`](../../../triage/docs/adr/0002-triage-v1-implementation-choices.md)
(volume, not content density, is what gates episodic retrieval; v1 has
too few Episodes for semantic retrieval to outperform structured lookup)
— this ADR adopts it rather than re-arguing it. Strict key equality, no
embeddings, no API calls, ever.

**The write moment** — record only executed incidents vs. every decided
incident. Chose every decided incident: the Episode is written by the
execute node at decision time — approved-executed, approved-dry-run, and
rejected alike. A rejection concerns the proposal, not the diagnosis;
the root cause stands. Only the runbook-drafting side of the loop
filters to resolved, executed incidents.

**Retrieval scoring** — one scorer shape for both memory types, and the
same one triage's memory retrieval proved: 3 per shared cause-like key,
2 for the same procedure, 1 per shared evidence key, threshold 2, top 3,
newest first. Chose it for Episodes (the investigate node seeds the LATS
objective with the top matches) and for Runbooks (the propose node
prepends the top matches as context ahead of the proposer call). Below
threshold — or with an empty store — the behavior is exactly as if
memory never existed.

**Procedural memory** — a model-maintained store vs. committed,
operator-authored Runbook files with strict YAML frontmatter. Chose the
committed files (`dispatch/runbooks/*.md`): each Runbook carries its
structured contract — slug, title, procedure, symptoms as key:value
match keys, ordered steps, and one resolution `{action, args}` from the
fixed vocabulary. Parsing validates every field, so a bad runbook fails
loudly at load instead of shipping one that can never match. Matching is
structured-symptom and procedure only — no log-pattern matching in v1 —
and `{placeholder}` resolution args bind from the incident's evidence
keys at proposal time; an unbound placeholder yields no proposal.

**The learning loop** — auto-promoting runbooks vs. a human gate. Chose
the gate, twice over. `dispatch close <id> --outcome resolved|unresolved
[--evidence …]` is valid only for approved-executed incidents; it
appends the Outcome to the Incident Record and to the Episode (a
surgical single-line rewrite — the one exception to append-only, and the
corrupt lines still survive byte-identical). On resolved with a real
remediation and no matching committed Runbook, a deterministic template
(no LLM call — ADR-0002) drafts a Runbook from the Episode's own record
into `dispatch/runbooks/proposed/<procedure>-<incident_id>.md` with the
concrete args copied literally — a deterministic template cannot know
which IMSI or NF is incident-specific, so the operator generalizes at
promotion time — and prints the diff. The loop proposes, a human
disposes: promotion is a manual move into the committed directory, and
the loop never edits or deletes a committed Runbook.

**The confirmation check** — invent a verification command vs. reuse the
Golden-baseline comparator. Chose reuse: close prints a suggested
confirmation check that is the same deterministic comparison the
detect-kpi command performs, over fresh post-remediation captures (for
a rerun_capture remediation, the capture scenario itself).

## Consequences

- The entire memory stage is file I/O and dict lookups: Groq-free,
  offline, and behind the build-graph seams, so the test suite never
  costs a call (ADR-0002).
- The Episode store is append-only except for the one surgical close
  rewrite; nothing else mutates history.
- The operator is the only writer to the committed Runbooks — the model
  can propose new procedure knowledge but never self-apply it.
- Memory is silent when irrelevant: thresholds and empty stores degrade
  to exactly the pre-memory pipeline.
- The loop fills the library gradually: one seed Runbook ships with the
  stage (derived from the committed sample incident, so every word of it
  traces to real committed evidence), and resolved incidents accrete
  proposals over time.
