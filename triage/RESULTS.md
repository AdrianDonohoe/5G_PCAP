# triage eval results

The committed record of the offline eval harness (`evals/run_eval.py`; see
[evals/README.md](evals/README.md) for what it measures and why it never
runs in pytest). Each entry below is a single real run pinned to the commit
it measured — the table names exactly what it measured, nothing else. Live
Groq calls on every run (ADR-0002), so the document is generated locally
only: no pytest test and no CI job produces it.

## 2026-08-20 — commit `1d9910e`

- **Commit:** `1d9910e` ("Update the READMEs for the cross-plane span")
- **Generator model:** gpt-oss:120b on Groq (`openai/gpt-oss-120b`)
- **Judge model:** qwen3.6-27b on Groq (`qwen/qwen3.6-27b`) — a model family
  distinct from the generator
- **Protocol:** 3 runs per fixture; each run searches the fixture's own
  plane and the judge scores every completed Hypothesis across four 0–1
  dimensions (Accuracy, Specificity, Evidence, Causality)

### Per fixture

| fixture | type_accuracy | diagnosis_quality |
|---|---|---|
| auth_failure | 1.000 | 1.000 |
| registration_reject | 1.000 | 1.000 |
| registration_timeout | 1.000 | 1.000 |
| pdu_session_reject_slice | 1.000 | 1.000 |
| pdu_session_reject_other | 1.000 | 1.000 |
| pdu_session_timeout | 1.000 | 0.925 |
| sbi_udm_timeout | 1.000 | 0.965 |
| sbi_nssf_reject | 1.000 | 1.000 |
| n4_upf_timeout | 1.000 | 1.000 |

### Overall

- **type_accuracy:** 1.000 (target >= 0.889 — 8/9 over the nine fixtures)
- **diagnosis_quality:** 0.988 (target >= 0.700)
- **completed runs:** 27/27 (60 hypotheses judged)
- **dimension means:** accuracy 0.99, specificity 0.99, evidence 1.00,
  causality 0.98

## Regenerating this document

```
cd triage
uv run python evals/run_eval.py    # needs GROQ_API_KEY; ~an hour of real Groq calls
```

The harness prints the summary block at the end and checkpoints
`evals/results.json` after every fixture (an interrupted run resumes with
`--resume`). Transcribe the printed summary into a new section above,
updating the commit, models, and date — the exact values are in
`evals/results.json`. Re-run and commit the table whenever the agent, the
fixtures, or the judge model change: a table that doesn't name the code it
measured is noise.
