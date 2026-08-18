# Post-incident report writer: deterministic Markdown over a triage run

`triage analyze` emits hypotheses as machine-readable JSON and prints the
winning Trajectory only under `--verbose` — nothing in the repo turns a run
into a shareable post-incident artifact. A report has to exist somewhere:
operators hand writeups to each other, and the sandbox eval is a loop of
capture → decode → triage → eyeball that ends in a human reading prose.
This ADR adds the report writer: a deterministic Markdown assembler whose
only LLM prose is the Episode's narrative (the search's finalize step
already wrote it) — everything else is assembled, verified, and formatted
by code. It also discharges ADR-0003's promise that the report writer
traverse the spec graph without re-deriving it.

## Status

accepted

## Considered Options

**Prose** — LLM-written report vs. deterministic template. Rejected the
LLM writer: it spends a Groq call on every report, its output is
nondeterministic across re-runs of the same results file, and it would
either duplicate the Episode's narrative or tempt it to invent detail the
search never observed. Chose the template: the root-cause section is the
Episode's narrative verbatim, evidence lines are marked `[verified]` by
re-checking each citation against the decode, and every other section
(timeline, KPIs, search path, spec context) is formatted data — so a
report is reproducible byte-for-byte from its inputs.

**Format** — Markdown vs. HTML/PDF. Chose Markdown: it diffs in git, it
round-trips through the terminal, chat, and wiki tooling the project
already assumes (READMEs, ADRs, sandbox notes), and it needs no rendering
toolchain. A PDF/HTML renderer can be a later formatting pass over the
same Markdown; none is needed now.

**One report per run vs. per incident** — chose one file per run: an
operator triaging a capture wants the whole capture in one scroll, with a
per-incident overview table up front. The single-incident case (the common
one) renders the full per-incident shape with an H1 title and no table.

**Search path** — re-run the search to recover the trajectory vs. save it.
Rejected re-running: `triage report` must be re-runnable offline and free
(no Groq), and a re-run could converge differently. Chose saving the
winning trajectory in the results file (`triage analyze --out` gains a
`trajectory` field, alongside `detail`), with honest degrade lines for
results files that predate it: "(trajectory not recorded in this results
file)".

**Spec context** — the embedding index vs. the spec graph. Chose the
graph (ADR-0003): the report asks exact questions ("5GMM cause #21"), and
`resolve()` + `entity_block()` answer them deterministically with typed
entities — the `defined_in`/`co_mentioned` structure is reused, not
re-derived. Per cited evidence, the report resolves the message entity
(normalize() bridges decoder forms like "5GMMStatus") and the cause entity
when the message names a NAS/PFCP protocol (the prefix disambiguates
shared values like 67; NGAP causes are ENUMERATED-only and never queried
by number). Blocks are deduped by entity id, capped at 6, and any graph
failure silently omits the section — the report must never kill itself
over a cache rebuild.

**Wiring** — `--report` flag on `triage analyze` vs. a standalone
subcommand. Chose both, sharing one writer module (`triage/report.py`):
`triage analyze --report PATH` writes the report in-process beside the
JSON payload, and `triage report --results R.json --n2 N2.json [--n4]`
re-renders a saved run offline. The saved-run path is what makes reports
re-runnable after the fact — the analyze path covers the one-shot flow.
Both keep their stdout contract unchanged: analyze prints JSON, report
prints Markdown.

## Consequences

- The saved results schema grows additively (`detail`, `trajectory`);
  every key is read with `.get()`, so old results files render with
  explicit not-recorded lines. New tests pin the extended schema.
- `[verified]` re-uses `grounded_evidence` — the same completeness-bar
  semantics `_finalize` enforces (renamed public; one call site). The
  report can only re-verify, never re-trust, a saved Episode.
- The pytest suite stays offline and free (ADR-0002): template tests run
  against synthetic runs and a tiny fixture graph in tmp_path; one
  real-corpus spec-context case shares a session-scoped graph build
  (~3 s) in tmp.
- `triage report` is the first fully offline, Groq-free command in the
  CLI — the zero-incident `analyze --report` run works without
  `GROQ_API_KEY`, and the docstring now says so.
- The only LLM prose in a report is the Episode's narrative; any future
  report-prose feature (e.g. an executive summary) is a deliberate new
  ADR, not an edit to a template.
