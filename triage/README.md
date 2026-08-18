# triage

LLM-agent root-cause hypothesis generation for failed 5G Registration and
PDU Session procedures and SBI service transactions. One-shot per failed
Incident, consuming 5gcap's decode output (N2, N4, SBI planes) as its
evidentiary substrate; evaluated against the sandbox's
failure-injection fixtures.

The domain language (Incident, Evidence, Hypothesis, incident_type,
Trajectory, Topology, Episode, Post-incident report, type_accuracy,
diagnosis_quality) lives in
[CONTEXT.md](./CONTEXT.md). Architecture and implementation choices are in
the ADRs ([0001](./docs/adr/0001-lats-coala-triage-agent.md),
[0002](./docs/adr/0002-triage-v1-implementation-choices.md),
[0003](./docs/adr/0003-spec-graph-typed-entities-and-hybrid-retrieval.md),
[0004](./docs/adr/0004-post-incident-report-writer.md),
[0005](./docs/adr/0005-sbi-plane.md)). One real
invocation, decision by decision, is in
[docs/invocation-walkthrough.md](./docs/invocation-walkthrough.md).

## Layout

- `triage/` — the package (tools, LATS search, CoALA memory, CLI, the
  deterministic post-incident report writer; grows across the
  implementation steps)
- `triage/report.py` — deterministic post-incident report writer
  (ADR-0004): Markdown over a triage run, assembled from the saved
  results plus the decode
- `triage/specgraph.py` — typed spec-graph entities over the corpus
  (ADR-0003), built on first use and cached
- `tests/` — pytest suite
- `evals/` — the offline eval harness (`run_eval.py`: type_accuracy +
  diagnosis_quality over the labeled fixtures; real Groq calls, run
  explicitly, never inside pytest)
- `scripts/build_corpus.py` — one-time 3GPP spec fetch/chunk (see Development)
- `corpus/` — committed chunks.jsonl + manifest.json for the
  query_3gpp_spec tool; `corpus/cache/` (zips, embedding index, and the
  spec graph from ADR-0003) is gitignored
- `memory/` — episodic memory store (append-only episodes.jsonl, written by
  the consolidation step; runtime data, gitignored)

## Environment

`GROQ_API_KEY` is required for any triage invocation — v1 has no local-model
fallback (gpt-oss:120b via Groq; see ADR-0002). The corpus build and the
test suite run without it.

## Usage

```
5gcap analyze capture.pcap --json capture_n2.json   # decode (a 5gcap step)
triage analyze capture_n2.json [--n4 capture_n4.json] [--sbi capture_sbi.json] \
    [--out results.json] [--report report.md]
triage report --results results.json capture_n2.json [--n4 capture_n4.json] \
    [--sbi capture_sbi.json]
```

`triage analyze` auto-detects the failed Incidents in the decoded capture
(an explicit reject — a reject procedure or a cause-bearing
Reject/Status/Failure message — or a flow whose terminal message never
arrived), runs one LATS search per Incident, and prints the hypotheses to
stdout as a JSON array; progress and memory notes go to stderr. `--flow`
restricts detection to one flow, `--out` also writes the JSON to a file,
`--episodes-path` overrides the memory store, and `--verbose` prints each
winning Trajectory to stderr. With `--sbi`, failed SBI procedures (HTTP
status >= 400, or a request never answered) are added as their own
Incidents — they carry no flow_id, and `--flow` filters N2 incidents
only. Zero Incidents is an empty result with exit
0; exit 1 means the invocation itself failed (e.g. unset `GROQ_API_KEY`).

`triage report` re-renders a saved run (`--out`) as a deterministic
post-incident Markdown report — no Groq, no search, re-runnable offline;
it re-verifies each cited evidence item against the decode and annotates
the spec-graph context for the failure's causes and messages. `--report`
on `triage analyze` writes the same report in-process. The report prints
to stdout (Markdown, exit 0); `-o`/`--out` also writes it to a file, and
exit 1 means the invocation itself failed (e.g. unreadable results).

## Development

```
uv sync                        # installs the dev group (pytest, python-docx)
uv run pytest
uv run scripts/build_corpus.py # rebuild the pinned 19.x corpus
uv run python evals/run_eval.py  # offline eval (needs GROQ_API_KEY; see evals/README.md)
```

## v1 scope

Landed so far: the 3GPP corpus (TS 24.501 / 38.413 / 29.244 / 29.500 /
29.503 / 29.531, pinned 19.x),
the package skeleton, `query_topology`, `query_3gpp_spec` (local
embedding index over the corpus, built on first use and cached — the first
build embeds ~5000 chunks and takes ~15-30 min of CPU on this VM; afterwards
every run loads it from cache), episodic memory (`query_episodic_memory`
over the local JSON store — the Episode schema is the Pydantic model the
LATS search reuses for Hypothesis validation; every search objective is
also seeded with relevant past Episodes: deterministic retrieval scores
stored incidents by shared cause codes, message names, and procedure, and
injects the top matches as context, not evidence), and
`inspect_decoded_evidence` (deterministic Evidence handles over 5gcap's
--json exports: `kpis` / `flows` / `flow:<id>[:<i>]` / `unassociated[:<i>]`
/ `n4[:<i>]` / `sbi[:<i>]`, degrading to honest "no such evidence"
observations on bad
handles), the LATS search (`run_lats`: MCTS over Actions — deterministic
tool dispatch, gpt-oss:120b via Groq for expand/evaluate, and a
code-enforced completeness bar: a node completes only when its `finalize`
produces an Episode that validates AND cites evidence grounded in the
decode), the SBI plane (5gcap decodes the plaintext HTTP/2 on the NF
bridge's 7777; triage detects SBI Incidents, grounds SBI evidence on
service name + ts, and resolves TS 29.5xx service names through the spec
graph's SBI dialect — ADR-0005), and post-hoc CoALA consolidation
(`consolidate`: records the finalized Episode exactly once — a re-run of
the same capture dedups), and
the `triage analyze` CLI (Incident detection over 5gcap's decode output,
one LATS search per Incident, hypotheses as JSON on stdout), and the
offline eval harness (`evals/run_eval.py`: type_accuracy and
diagnosis_quality over the labeled fixtures — the six N2 scenarios plus
the two sbi_* ones, which join the run once their sandbox pcaps exist —
with the judge on a model
distinct from the generator), and the post-incident report writer
(`triage/report.py`, ADR-0004: deterministic Markdown over a saved run —
the Episode's narrative verbatim, evidence re-verified against the decode,
spec-graph context, timeline, KPIs, search path, and memory note —
reachable as `triage report` (offline, re-runnable) and
`triage analyze --report`).
