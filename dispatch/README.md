# dispatch

Event-driven incident orchestration for the 5G_PCAP stack. An Alarm
event — raised by a human or synthesized from KPI degradation — flows
through the Dispatcher, which fans out to the three specialist evidence
agents (PCAP, Log, KPI), correlates their findings, runs a root-cause
investigation, proposes a remediation from a fixed action vocabulary,
and gates execution on Human approval. Nothing executes without it.

Glossary: [`CONTEXT.md`](./CONTEXT.md) · architecture:
[`docs/adr/0001-incident-orchestration.md`](./docs/adr/0001-incident-orchestration.md) ·
remediation safety:
[`docs/adr/0002-remediation-proposal-and-executor.md`](./docs/adr/0002-remediation-proposal-and-executor.md)

## The workflow

Four subcommands, one artifact — the Incident Record. A complete real
run is committed at
[`docs/sample-incident-record.md`](./docs/sample-incident-record.md).

### 1. `detect-kpi` — the Alarm event

The KPI-degradation comparator runs 5gcap over the captures and compares
the computed KPIs against the committed Golden baseline: a procedure
success-rate drop, a latency KPI above twice golden, or any cause-bearing
reject across NAS/PFCP/SBI synthesizes the event JSON. Healthy KPIs print
nothing (exit 0) — no event.

```
uv run dispatch detect-kpi ../5gcap/tests/fixtures/n4_upf_timeout.pcap \
  --sbi ../5gcap/tests/fixtures/n4_upf_timeout_sbi.pcap \
  --n4 ../5gcap/tests/fixtures/n4_upf_timeout_n4.pcap > event.json
```

A human can also raise the event by hand — `source` may be `kpi`,
`alarm`, or `human` (the shape is in [`CONTEXT.md`](./CONTEXT.md)):

```
{
  "incident_id": "inc-human-12345678",
  "detected_at": 1788000000.0,
  "source": "human",
  "procedure": "pdu_session_establishment",
  "time_window": {"start": 1787999400.0, "end": 1788000000.0},
  "description": "Operator report: PDU session establishment failing on the lab core",
  "kpi": null,
  "captures": {
    "n2": "../5gcap/tests/fixtures/n4_upf_timeout.pcap",
    "sbi": "../5gcap/tests/fixtures/n4_upf_timeout_sbi.pcap",
    "n4": "../5gcap/tests/fixtures/n4_upf_timeout_n4.pcap"
  }
}
```

### 2. `handle` — the investigation

```
uv run dispatch handle event.json --stub stub.json
```

The stub seeds the record with placeholder evidence that the specialists
replace; an honest empty stub is just `{"evidence": []}`. The pipeline:

- **PCAP agent** — 5gcap decodes the event's captures and a
  `triage analyze` run analyzes the export; only findings with decode
  citations (e.g. `flow:1:13`) are recorded.
- **Log agent** — docker stdout logs for the event's time window, LLM
  extraction with a code-enforced exact-log-line grounding check.
- **KPI agent** — deterministic 5gcap analysis compared against the
  Golden baseline.
- **Correlation graph** — the findings linked into one picture.
- **Root-cause investigation** — a LATS search (triage's Tree) over the
  grounded evidence.
- **Proposal** — the LLM selects one action from the fixed five-action
  vocabulary and drafts a justification; the commands are rendered by
  deterministic templates, never LLM text.

The pipeline **stops at the approval gate**: the record ends
`**pending**`, nothing has executed. The record lands in
`dispatch/records/<incident_id>.md` and the checkpoint in
`dispatch/state/checkpoints.sqlite` (both gitignored runtime artifacts).
A duplicate incident is refused.

### 3. `approve` / `reject` — the Human decision

```
uv run dispatch approve <incident_id>              # dry-run: renders the commands
uv run dispatch approve <incident_id> --execute    # applies them to the sandbox
uv run dispatch reject <incident_id>               # records the rejection
```

Approval and rejection resume from the checkpoint store in fresh
invocations. The proposal hash recorded at handle time gates the whole
decision path — a tampered record refuses to be approved or rejected.
The bare `approve` is a dry-run in the execution sense only: it renders
the commands and records the approval on the Incident Record without
touching the sandbox; only `--execute` applies them. An incident is
decided once — a second `approve` or `reject` on the same record is
refused. A record that honestly produced no proposal cannot be approved
(the CLI says so and exits 1); `reject` is the way to close it.

### The action vocabulary (ADR-0002)

| action | args | effect |
|---|---|---|
| `restart_nf` | `{"nf": "<core service>"}` | restarts one sandbox core NF |
| `revert_config` | `{"path": "<config file under the sandbox>"}` | reverts a config file |
| `reseed_subscriber` | `{"imsi": "<14–15 digit IMSI>"}` | re-provisions a subscriber |
| `rerun_capture` | `{"scenario": "<one of the nine>"}` | re-runs a failure-injection capture |
| `observe_only` | `{}` | records the incident, applies nothing |

The nine `rerun_capture` scenarios (see
[`../sandbox/README.md`](../sandbox/README.md)): `auth_failure`,
`registration_reject`, `registration_timeout`,
`pdu_session_reject_slice`, `pdu_session_reject_other`,
`pdu_session_timeout`, `sbi_udm_timeout`, `sbi_nssf_reject`,
`n4_upf_timeout`.

## Sample Incident Record

[`docs/sample-incident-record.md`](./docs/sample-incident-record.md) is a
real end-to-end `n4_upf_timeout` run: `detect-kpi` over fresh lab
captures, then `handle` with the live specialists, ending pending at the
approval gate. The rendered command's checkout path is normalized
(`/path/to/5G_PCAP`); everything else is byte-faithful, and the proposal
hash still verifies the three proposal fields against the record. One
invisible detail is load-bearing: the proposal justification contains a
narrow no-break space (U+202F) in "NAS cause 38", and the hash covers
it — do not "fix" the typography.

## Preconditions

- The sandbox lab is up and seeded — see
  [`../sandbox/README.md`](../sandbox/README.md) — and the event's
  captures exist.
- `GROQ_API_KEY` is set: the log extraction, the root-cause search and
  the proposal are live Groq calls (ADR-0002: no local model fallback).
- Everything else — 5gcap, the KPI comparator, the templates, the
  record rendering — is deterministic and offline.

## Eval harness

[`evals/README.md`](./evals/README.md) runs all nine failure-injection
scenarios through this exact workflow against the live lab and scores
each pending record with a judge model distinct from the generator.

## Architecture

- [`docs/adr/0001-incident-orchestration.md`](./docs/adr/0001-incident-orchestration.md)
  — the orchestration decision: the LangGraph spine, the specialist
  fan-out, the correlation of multi-source evidence, the approval gate.
- [`docs/adr/0002-remediation-proposal-and-executor.md`](./docs/adr/0002-remediation-proposal-and-executor.md)
  — the remediation safety decision: the fixed action vocabulary,
  template-rendered commands, the proposal hash, and Human-gated
  execution.
