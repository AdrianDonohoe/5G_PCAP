# triage

LLM-agent root-cause hypothesis generation for failed 5G Registration and
PDU Session procedures. One-shot per failed Incident, consuming 5gcap's
decode output as its evidentiary substrate; evaluated against the sandbox's
failure-injection fixtures.

The domain language (Incident, Evidence, Hypothesis, incident_type,
Trajectory, Topology, Episode, type_accuracy, diagnosis_quality) lives in
[CONTEXT.md](./CONTEXT.md). Architecture and implementation choices are in
the ADRs ([0001](./docs/adr/0001-lats-coala-triage-agent.md),
[0002](./docs/adr/0002-triage-v1-implementation-choices.md)). One real
invocation, decision by decision, is in
[docs/invocation-walkthrough.md](./docs/invocation-walkthrough.md).

## Layout

- `triage/` — the package (tools, LATS search, CoALA memory, CLI; grows
  across the implementation steps)
- `tests/` — pytest suite
- `evals/` — the offline eval harness (`run_eval.py`: type_accuracy +
  diagnosis_quality over the labeled fixtures; real Groq calls, run
  explicitly, never inside pytest)
- `scripts/build_corpus.py` — one-time 3GPP spec fetch/chunk (see Development)
- `corpus/` — committed chunks.jsonl + manifest.json for the
  query_3gpp_spec tool; `corpus/cache/` (zips) is gitignored
- `memory/` — episodic memory store (append-only episodes.jsonl, written by
  the consolidation step; runtime data, gitignored)

## Environment

`GROQ_API_KEY` is required for any triage invocation — v1 has no local-model
fallback (gpt-oss:120b via Groq; see ADR-0002). The corpus build and the
test suite run without it.

## Usage

```
5gcap analyze capture.pcap --json capture_n2.json   # decode (a 5gcap step)
triage analyze capture_n2.json [--n4 capture_n4.json]
```

`triage analyze` auto-detects the failed Incidents in the decoded capture
(an explicit reject — a reject procedure or a cause-bearing
Reject/Status/Failure message — or a flow whose terminal message never
arrived), runs one LATS search per Incident, and prints the hypotheses to
stdout as a JSON array; progress and memory notes go to stderr. `--flow`
restricts detection to one flow, `--out` also writes the JSON to a file,
`--episodes-path` overrides the memory store, and `--verbose` prints each
winning Trajectory to stderr. Zero Incidents is an empty result with exit
0; exit 1 means the invocation itself failed (e.g. unset `GROQ_API_KEY`).

## Development

```
uv sync                        # installs the dev group (pytest, python-docx)
uv run pytest
uv run scripts/build_corpus.py # rebuild the pinned 19.x corpus
uv run python evals/run_eval.py  # offline eval (needs GROQ_API_KEY; see evals/README.md)
```

## v1 scope

Landed so far: the 3GPP corpus (TS 24.501 / 38.413 / 29.244, pinned 19.x),
the package skeleton, `query_topology`, `query_3gpp_spec` (local
embedding index over the corpus, built on first use and cached — the first
build embeds ~3500 chunks and takes ~15-30 min of CPU on this VM; afterwards
every run loads it from cache), episodic memory (`query_episodic_memory`
over the local JSON store — the Episode schema is the Pydantic model the
LATS search will reuse for Hypothesis validation), and
`inspect_decoded_evidence` (deterministic Evidence handles over 5gcap's
--json exports: `kpis` / `flows` / `flow:<id>[:<i>]` / `unassociated[:<i>]`
/ `n4[:<i>]`, degrading to honest "no such evidence" observations on bad
handles), the LATS search (`run_lats`: MCTS over Actions — deterministic
tool dispatch, gpt-oss:120b via Groq for expand/evaluate, and a
code-enforced completeness bar: a node completes only when its `finalize`
produces an Episode that validates AND cites evidence grounded in the
decode), and post-hoc CoALA consolidation (`consolidate`: records the
finalized Episode exactly once — a re-run of the same capture dedups), and
the `triage analyze` CLI (Incident detection over 5gcap's decode output,
one LATS search per Incident, hypotheses as JSON on stdout), and the
offline eval harness (`evals/run_eval.py`: type_accuracy and
diagnosis_quality over the six labeled fixtures, with the judge on a model
distinct from the generator).
