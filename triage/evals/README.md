# triage evals

The offline eval harness for `type_accuracy` and `diagnosis_quality`
(CONTEXT.md), over the nine labeled failure-injection fixtures in
`5gcap/tests/fixtures/` — the two `sbi_*` and one `n4_upf_timeout` fixtures
join the run only once their sandbox pcaps exist. Runs explicitly — never
inside the default pytest suite, because every fixture run costs real Groq
calls (ADR-0002).

## Run

```
uv run python evals/run_eval.py                 # all enabled fixtures x 3 runs
uv run python evals/run_eval.py --fixtures auth_failure --runs 1   # smoke
uv run python evals/run_eval.py --resume        # skip runs already in --out
```

Results checkpoint to `--out` (default `results.json`) after every fixture,
so an interrupted run resumes with `--resume` instead of re-paying the
completed fixture-runs. `GROQ_API_KEY` must be set. Decoding uses 5gcap's
CLI via subprocess (the JSON contract), so 5gcap's uv environment must be
synced.

## Targets

- `type_accuracy` >= (n-1)/n over the enabled fixtures — 8/9 once all nine
  are enabled — fixture-level mean of exact `incident_type` matches against
  the fixture's `.label.json`.
- `diagnosis_quality` >= 0.7 — run-level mean of four 0–1 dimension scores
  (Accuracy, Specificity, Evidence, Causality) from an LLM judge; a run
  whose search completes no Hypothesis scores 0.0.

## Design notes

- **Judge model**: `qwen/qwen3.6-27b` on the same Groq account — a model
  family distinct from the generator (gpt-oss:120b), which is what
  "distinct" exists for. The task's original pick (llama-3.3-70b-versatile)
  is not served on this account; the `JUDGE` constant in `run_eval.py`
  swaps it in one place.
- **Judge grounding**: the judge scores each Hypothesis against the
  Incident's decoded messages (a flow brief), not against the ground-truth
  label — Accuracy means "no invented facts", so `diagnosis_quality` does
  not duplicate `type_accuracy`. The brief carries the flow's time span and
  absence of procedure records, and the rubric treats the missing terminal
  message as the mechanism for timeout shapes — without that, the judge
  penalizes correct timeout hypotheses for not naming which element failed
  when the decode cannot distinguish them.
- **Episodic memory reset**: each fixture run uses a fresh temp
  `episodes.jsonl`, so consolidation never dedups across runs.
- **Plane filter**: each fixture searches only its own plane's incidents —
  the six N2 fixtures search N2 incidents only, the two `sbi_*` fixtures
  (which decode `<name>.pcap` and `<name>_sbi.pcap`) search SBI incidents
  only, and `n4_upf_timeout` (which also decodes `<name>_n4.pcap`) searches
  N4 incidents only. Without it, `pdu_session_timeout`'s SBI view — which
  legitimately shows an unanswered Nsmf_PDUSession request — would be
  searched against an N2 label.
- **The `spec` Action** may trigger the embedding-index build on the first
  eval run (~15–30 min CPU on this VM); afterwards it loads from
  `triage/corpus/cache/`.
- **Results** land in `results.json` (gitignored): per-run
  `type_accuracy`, per-Hypothesis dimension scores + judge comments, and a
  summary block with the targets.
