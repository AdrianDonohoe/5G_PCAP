# dispatch eval harness

The live eval for the dispatch pipeline: the ten sandbox
failure-injection scenarios run as Alarm events through the real pipeline
against the live lab, and an LLM judge distinct from the generator scores
each Incident Record's quality. This is the only runner that touches Groq
(ADR-0002) — pytest never executes it.

## Preconditions

The sandbox lab must be up, same as for any capture run (see
`sandbox/README.md`):

```
cd ../../sandbox/core && docker compose up -d
./seed/seed_subscribers.sh        # one-time, or after the volume is wiped
```

Plus `GROQ_API_KEY` in the environment (the pipeline's live defaults and
the judge all raise without it).

## Usage

From the dispatch directory:

```
uv run python evals/run_eval.py                 # all ten, 3 runs each
uv run python evals/run_eval.py --scenarios n4_upf_timeout auth_failure
uv run python evals/run_eval.py --runs 1
uv run python evals/run_eval.py --resume        # resume from results.json
uv run python evals/run_eval.py --out results-trial.json --work work-trial
```

Per scenario the harness captures once (~1 min in the lab), runs the
real `detect-kpi` CLI over the captures, decodes once for the judge's
ground, and then per run executes one fresh pipeline pass ending at the
approval gate — the pending Incident Record is the judged artifact.
Checkpoint/resume writes `{"summary": ..., "runs": [...]}` to `--out`
after every scenario (the summary carries the final report text once
the run completes); `--resume` skips completed (scenario, run) pairs,
retries runs whose previous attempt errored, and never re-captures a
scenario whose runs are all done.

`results.json` and `work/` are gitignored runtime artifacts.

## Results

One entry per scenario in `results.json`:

- `label` — the ground-truth `{incident_type, scenario}` label from
  `capture.sh`, a reference column in the report, never judge input
- `event` — the Alarm event the real `detect-kpi` comparator produced,
  or `null` for a detection miss (healthy KPIs — reported, not
  fabricated)
- `facts` — the merged-decode brief the judge grounded on
- `runs` — per run: the five dimension scores + judge comment, the
  mean quality, and the pending record's location; a failed pass is an
  `error` entry on that run, retried on resume

The printed report lists per-scenario quality and dimension means, the
overall means, and any missed or errored scenarios. There are no pass/fail
thresholds — the report is the raw measurement.

## Design notes

- **The judge model is distinct from the generator** — Qwen 3.6-27b
  against the pipeline's gpt-oss-120b (same doubled `openai/` vendor
  prefix trick as triage's harness, same Groq base). dspy is
  reconfigured to the judge's LM on every call, because the pipeline's
  generator reconfigures dspy whenever it runs.
- **Five dimensions** — accuracy, specificity, evidence, causality, and
  proposal. The proposal dimension scores the #30 surface triage's
  judge lacks: does the chosen action address the root cause and does
  the justification connect them. A record that honestly reports no
  proposal scores proposal 0.0 — the honesty is not penalized.
- **The judge grounds in decoded captures only** — the brief carries
  the merged N2/N4/SBI export's failure shapes. The scenario label
  never reaches the judge: accuracy means "no invented facts", not
  "found the injected failure".
- **Capture once per scenario** — the capture is the expensive live
  step. Runs reuse the same captures with fresh per-run state/records
  dirs, so the identical incident id is re-runnable and the LLM legs
  (extraction, search, proposal) vary across runs without extra lab
  time.
- **The pipeline stops at the approval gate** — the pending record is
  the judged artifact. Remediation is never applied: a `restart_nf` or
  `revert_config` would mutate the shared lab and contaminate the next
  scenario's capture.
- **Detection misses are reported** — if a scenario's KPIs come back
  healthy, `detect-kpi` produces no event and the harness records the
  miss rather than synthesizing one. The eval measures detection end to
  end.
