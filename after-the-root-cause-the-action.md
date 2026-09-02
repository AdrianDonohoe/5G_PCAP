# After the Root Cause, the Action: A 5G Incident Orchestrator

*An alarm becomes an incident, three specialists bring grounded evidence, one imported tree search finds the root cause — and nothing executes until a human approves it.*

The first article ended where most diagnosis tools end: with an answer. The triage agent could explain a 5G failure — every claim checked against the packet capture — but an explanation is not an action. Someone still had to read the report, decide what to do, and do it. If the agent was ever going to move from the lab bench to anything like an operator's workflow, it needed a second half: the part that turns a diagnosis into a decision, and a decision into an execution — under human control, with everything written down.

That second half is **dispatch**, the new project in the stack. It is event-driven incident orchestration: an Alarm event — raised by a human or synthesized from KPI degradation — flows through a Dispatcher that fans out to three specialist evidence agents, correlates what they find, runs a root-cause investigation, proposes a remediation from a fixed vocabulary of five actions, and stops. It stops at an approval gate, with a human on the other side. Nothing executes without that human. After the decision, the incident is closed with an Outcome, and the close step feeds a learning loop that drafts new runbooks — but never publishes them. The loop proposes, a human disposes.

![Dispatch pipeline — one incident, end to end: raise or detect, handle, human-gated execution, close + learn](https://raw.githubusercontent.com/AdrianDonohoe/NetCortex/master/dispatch/docs/diagrams/pipeline.png)

*The dispatch pipeline, generated with [fireworks-tech-graph](https://github.com/yizhiyanhua-ai/fireworks-tech-graph). Full-size SVG and the diagram IR live in [`dispatch/docs/diagrams/`](https://github.com/AdrianDonohoe/NetCortex/tree/master/dispatch/docs/diagrams).*

## From diagnosis to decision

Two things changed between the articles, and both matter.

The first is the relationship between the projects. Triage is not rewritten; it is imported. Dispatch's root-cause investigation literally runs triage's LATS tree search as a library, and its PCAP specialist shells out to the deterministic decoder that the first article was about. Dispatch is a consumer of triage, the way triage is a consumer of the decoder: each layer adds a decision, and none of them re-implements the layer below.

The second is the brand. The repo is now **NetCortex** — "an agentic AI platform for autonomous network operations" — and dispatch is its second project, with a change-impact agent, a cross-domain incident-correlation project, and a digital twin on the roadmap. The 5G analyzer keeps its name; the platform around it grew. (Old links from the first article keep working — GitHub redirects them.)

Where triage asks *what happened?*, dispatch asks *what happens next?* — and its answer is always "ask a human."

## The alarm event: raised or detected

Every incident starts as an Alarm event: a small JSON document with an incident id, a time window, a procedure, and the captures to analyze. There are two ways to make one.

A human can raise it by hand — `source: "human"`, a description like "PDU session establishment failing on the lab core." That path matters, because an operator's phone call is an input too.

Or the system can detect it. `detect-kpi` runs the 5gcap analyzer over a set of captures and compares the computed KPIs against a committed Golden baseline. Three conditions synthesize the event: a procedure success-rate drop, a latency KPI above twice golden, or any cause-bearing reject across NAS, PFCP, or SBI. Healthy KPIs print nothing and exit 0 — no event, no noise, nothing to read.

```
{
  "incident_id": "inc-human-12345678",
  "detected_at": 1788000000.0,
  "source": "human",
  "procedure": "pdu_session_establishment",
  "time_window": {"start": 1787999400.0, "end": 1788000000.0},
  "captures": {
    "n2": "../5gcap/tests/fixtures/n4_upf_timeout.pcap",
    "sbi": "../5gcap/tests/fixtures/n4_upf_timeout_sbi.pcap",
    "n4": "../5gcap/tests/fixtures/n4_upf_timeout_n4.pcap"
  }
}
```

The event is the contract. Everything downstream consumes it and nothing else — the Dispatcher never asks for more input than the event names.

## Three specialists, three grounding contracts

The Dispatcher fans the event out to three specialist agents, one per evidence source. The design constraint is the same one that ran through the first article: an agent may say only what its source proves.

- **The PCAP agent** decodes the event's captures with 5gcap and runs a triage analysis over the export. Every finding must carry a decode citation — a frame reference like `flow:1:13` — and findings without one are dropped, not softened.
- **The Log agent** pulls the docker stdout logs for the event's time window and has the LLM extract findings — but a code-enforced check requires every citation to be a verbatim log line. Paraphrase is not evidence.
- **The KPI agent** is fully deterministic: computed KPI values against the Golden baseline, no free text at all. Where the other two agents can misquote, this one cannot even talk.

Each contract is enforced in code, not in the prompt. The LLM proposes the finding; the code checks the citation; a finding that fails its check vanishes from the record. This is the division of labor from the first article, one level up: the model decides what to say, the code decides whether it counts.

## Correlation without guessing

Three sources produce three lists of findings, each grounded in its own citation. The correlation step joins them — and it is the most deliberately boring code in the project.

Findings link only by strict equality of shared key values inside the event's time window. A key value shared by more than two findings is ambiguous and links nothing. Two findings that disagree on a shared key never link. There is no similarity score, no embedding, no "close enough" — the pipeline never guesses a join, because a guessed join is a fabricated cause.

The committed sample run shows what that looks like in practice: twenty grounded findings, and one honest line — `no links`. The correlation stage found nothing it could join, said so, and the pipeline carried on. The record does not pretend a picture emerged when one didn't.

## The root-cause search, imported

Over the correlated inventory, dispatch runs the same tree search triage does: LATS, with the LLM proposing nodes, code executing them, an evaluator scoring them, and backpropagation choosing what to expand. Dispatch imports triage's Tree directly — same search, new context.

One new input matters. Before the search starts, the Dispatcher scores the incident against past **Episodes** — the structured memory of every previously decided incident — and seeds the search's objective with the best matches. Note the direction of the arrow: memory is context, never evidence. It can steer what the agent tries, the way a runbook steers an engineer. It cannot be cited, because memory is not a measurement.

An eval harness runs all ten failure-injection scenarios through this exact workflow against the live lab and scores each pending record with a judge model distinct from the generator — the same two-model setup from part 1.

## A vocabulary of five actions

The search ends at a root cause. The next node must turn it into an action — and this is where dispatch's real safety design lives. The proposer does not write commands. It selects one action from a fixed vocabulary of five:

| action | args | effect |
|---|---|---|
| `restart_nf` | `{"nf": "<core service>"}` | restarts one sandbox core NF |
| `revert_config` | `{"path": "<config file under the sandbox>"}` | reverts a config file |
| `reseed_subscriber` | `{"imsi": "<14–15 digit IMSI>"}` | re-provisions a subscriber |
| `rerun_capture` | `{"scenario": "<one of the ten>"}` | re-runs a failure-injection capture |
| `observe_only` | `{}` | records the incident, applies nothing |

The LLM picks one action, fills its arguments, and drafts a justification. The commands themselves are rendered by deterministic templates from those arguments — never LLM text, so there is no prompt-injection surface between proposal and shell. A render rail rejects unknown NFs, path escapes, bad IMSIs, and unknown scenarios; an invalid selection yields no proposal, and the record says so honestly.

The proposal is then hashed — action, arguments, and justification — and the hash is written into the Incident Record. Everything downstream keys on it. In the committed sample, the justification contains a narrow no-break space in "NAS cause 38", and the hash covers that byte. I have never once been tempted to "fix" the typography, because the moment I do, the hash stops verifying. The record is a legal document in a way I did not fully appreciate until I had to treat a whitespace character as load-bearing.

## The approval gate

The pipeline stops. The Incident Record lands in the records directory, marked **pending**, its execution log empty. This is not a pause in a loop — it is a LangGraph interrupt, and the process ends. Nothing has run.

Deciding is a separate, deliberate act:

```
uv run dispatch approve <incident_id>              # dry-run: renders the commands
uv run dispatch approve <incident_id> --execute    # applies them to the sandbox
uv run dispatch reject <incident_id>               # records the rejection
```

Approve and reject are fresh processes that resume the checkpointed graph from a sqlite store — same incident, different day, different terminal. Before anything runs, the executor re-checks the proposal hash: a tampered record refuses to execute. A bare `approve` renders the commands and records the decision without touching the sandbox; only `--execute` applies them. An incident is decided once. And a record that honestly produced no proposal cannot be approved at all — the CLI says so and exits; `reject` is the way to close it.

> My design rule: the agents say only what their sources prove; the code decides what executes; the human decides what happens.

## One real incident, end to end

The repo commits a complete real run — `inc-kpi-20a3050c`, from the `n4_upf_timeout` failure-injection scenario — so the record format is not aspirational. Read it; every claim above has a concrete example there.

The event was detected, not raised: `procedure_success_rate` came back at 0.07 against a golden of 1.0, and `pdu_session_time_ms` at 1,744 ms against a golden of 1.6 ms. The KPI section listed thirteen procedure failures, each a PDU session establishment rejected with NAS cause 38 — "Network failure."

The PCAP agent found the explicit rejects, with decode citations. The KPI agent found the deviations and the cause-bearing rejects, with computed values. The correlation stage, as I said, linked nothing. The root-cause search concluded:

> The session establishment repeatedly failed due to NAS cause 38 indicating a network failure, as shown by explicit reject messages and KPI failures.

The proposer selected `restart_nf` with `{"nf": "smf"}`, and justified it — restarting the SMF to clear the faulty internal state generating the rejects. The template rendered exactly one command: a docker compose restart of the SMF in the sandbox.

And there the record ends: proposal hash `803c4324…`, approval status **pending**, execution log empty. That is the whole point of the artifact. The most capable moment of the pipeline is the one where it does nothing and waits.

## Memory and the learning loop

A decided incident is not forgotten. Two stores, both plain file I/O — no embeddings, no vector database, no API calls — keep the history.

**Episodes** — an append-only JSONL of every decided incident: its signature, the action and arguments, the root cause, the decision, and later its Outcome. The investigate node scores past episodes structurally (3 points per shared cause key, 2 for the same procedure, 1 per shared evidence key; threshold 2, top 3, newest first) and seeds the search objective with the matches. An empty store changes nothing.

**Runbooks** — committed, operator-authored procedural memory: one resolution from the five-action vocabulary per file, with symptoms as key:value match keys. The proposer matches the incident against them and binds `{placeholder}` arguments from the incident's evidence. These are the playbooks a human wrote, not the ones the system dreams.

The loop closes when the operator runs `close` with an Outcome — `resolved`, with the evidence for it, or `unresolved`. `close` is valid only for incidents that were approved *and* executed; pending, dry-run-approved, rejected, and already-closed incidents are refused. If the outcome is resolved, the action was real, and no committed runbook already covered it, the loop stages a draft — a deterministic template with the episode's concrete arguments copied literally — into `runbooks/proposed/`, and prints the diff for review. Promotion is manual. The loop never edits the committed runbook library.

**The loop proposes, a human disposes.** Learning accumulates, but it never self-applies. The system gets better at proposing; a person decides what the system becomes.

## What I haven't done yet

- Everything executes against the sandbox lab, not a live network — and the action vocabulary is deliberately small enough to do no real damage even if it did.
- Detection compares against a static golden baseline. An adaptive, learned baseline is the digital twin project's problem, not dispatch's.
- Correlation is strict equality. Near-miss matching — fuzzy joins, partial matches — is deliberately absent, and doing it right is the planned cross-domain incident-correlation project.
- The gate is a CLI. There is no alerting surface, no chat interface; a human has to walk to the terminal. That is a feature for now.
- The learning loop is young: the runbook library starts empty and grows only as fast as humans promote drafts.

The honest summary: dispatch is the second half of a diagnosis, built to be boring in exactly the places where an autonomous system should be boring.

## Read more

- **Repo** — [github.com/AdrianDonohoe/NetCortex](https://github.com/AdrianDonohoe/NetCortex)
- **The workflow, command by command** — [`dispatch/README.md`](https://github.com/AdrianDonohoe/NetCortex/blob/master/dispatch/README.md)
- **The real incident** — [`dispatch/docs/sample-incident-record.md`](https://github.com/AdrianDonohoe/NetCortex/blob/master/dispatch/docs/sample-incident-record.md)
- **The safety decisions** — [`dispatch/docs/adr/0002-remediation-proposal-and-executor.md`](https://github.com/AdrianDonohoe/NetCortex/blob/master/dispatch/docs/adr/0002-remediation-proposal-and-executor.md) (the fixed vocabulary, the proposal hash, human-gated execution) and [`0003-structured-memory-and-gated-learning.md`](https://github.com/AdrianDonohoe/NetCortex/blob/master/dispatch/docs/adr/0003-structured-memory-and-gated-learning.md) (episodes, runbooks, the gated loop)
- **The eval harness** — [`dispatch/evals/README.md`](https://github.com/AdrianDonohoe/NetCortex/blob/master/dispatch/evals/README.md) — all ten failure-injection scenarios, scored by a judge distinct from the generator
- **The lab** — [`sandbox/README.md`](https://github.com/AdrianDonohoe/NetCortex/blob/master/sandbox/README.md) — Open5GS + UERANSIM, ten failure-injection scenarios
- **Part 1** — [The LLM Proposes, the Code Disposes](https://github.com/AdrianDonohoe/NetCortex/blob/master/the-llm-proposes-the-code-disposes.md)
