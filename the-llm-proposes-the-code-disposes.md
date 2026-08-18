# The LLM Proposes, the Code Disposes

*A deterministic decoder, a failure-injection lab, and a tree-search agent that explains 5G failures — with every citation checked against the packet capture.*

When a 5G device won't attach, someone opens Wireshark. Somewhere in the NGAP and NAS signaling between the radio and the core sits a Registration Reject with a cause code — or worse, a procedure that simply never completes. Finding the message is mechanical. Explaining *why* it happened is where the hours go.

I've spent a lot of those hours myself, and I kept noticing the same two things. LLMs are genuinely good at the explaining part — and genuinely good at inventing evidence. Give one a decoded transcript and it will produce a coherent root-cause story, coherent enough that you can't spot the made-up message without re-reading the capture yourself.

[5G_PCAP](https://github.com/AdrianDonohoe/5G_PCAP) is my experiment in whether you can have the explanation without the invention. The answer I landed on is an architecture where the LLM is never the source of truth about the capture. The model can propose, score, and narrate; the code verifies. Three components:

- **`5gcap`** — deterministic decode of NGAP/NAS (N2) and PFCP (N4): per-UE flows, procedure pairing, KPIs.
- **`sandbox`** — a real Open5GS core plus UERANSIM radio, with six scripted failure injections, each labeled with ground truth.
- **`triage`** — an LLM agent (LATS tree search + CoALA memory) that turns a decoded failure into a grounded root-cause hypothesis, evaluated by a second, different model.

```
pcap ──► 5gcap decode ──► incident detection ──► search objective
                        (code, fixed shapes)     (+ memory context)
                                                   │
  ┌────────────────────────────────────────────────┘
  ▼
 LATS search — one per incident
  expand    (LLM)   propose actions
  execute   (code)  dispatch tools · ground finalize
  evaluate  (LLM)   score trajectory
  backprop  (code)  UCB1 · repeat, ≤10 rollouts
  │
  ▼
 grounded Episode ──► episodic memory
  │
  ▼
 stdout JSON ──► judge (a different LLM) ──► scores
```

## Ground truth first: decode without guessing

Everything downstream depends on the decode, so I kept the decode deliberately boring. `5gcap` uses pycrate's ASN.1 engines for NGAP/NAS/PFCP and scapy for pcap I/O and SCTP reassembly; it maps messages to per-UE flows, pairs Registration and PDU-session procedures start-to-end, and computes KPIs (attach time, session establishment time, procedure success rate).

My rule is lenient-but-honest: unknown IEs are annotated `unparsed`, never fatal, and anything security-protected that can't be read is surfaced as unread rather than guessed. A decoder that confidently misparses is worse than one that admits what it can't see — especially when its output is about to become *evidence* for an LLM that would happily build on a wrong parse.

## A failure lab with labels

You can't evaluate a root-cause explainer without known failures, so I built a lab that produces them on demand: a full Open5GS core (AMF, SMF, UPF, NRF, AUSF, UDM, and friends) plus a UERANSIM gNB with three UEs. `capture.sh --scenario <name>` injects one of six failures into UE1 while UE2/UE3 stay golden in the same capture, and writes a `.label.json` ground-truth file alongside it:

| Scenario | Injection | Wire shape |
|---|---|---|
| `auth_failure` | wrong Ki on UE1 | SYNCH FAILURE #21 → REGISTRATION REJECT #111 |
| `registration_reject` | unprovisioned IMSI | REGISTRATION REJECT, cause #7 |
| `registration_timeout` | AMF paused | RegistrationRequest left open, UE retries |
| `pdu_session_reject_slice` | second session on SST 2 | 5GMM STATUS #91 |
| `pdu_session_reject_other` | APN not in UDM | 5GSM REJECT, cause #67 |
| `pdu_session_timeout` | SMF SBI blackholed | hang ~11 s, then 5GMM #90, retries |

Two shapes deliberately differ from the 3GPP textbook, because they are what Open5GS actually emits: a wrong Ki ends in REGISTRATION REJECT #111, not AUTHENTICATION REJECT #20, and the DNN failure comes back as #67, not #27. The fixtures record reality — the agent triages a real network, not the spec's ideal world. The timeout scenarios were the hard part. Pausing the SMF container doesn't hang anything (the NRF purges a heartbeat-less NF and the AMF answers instantly), so the scenario blackholes the SMF's SBI port from inside its own netns — heartbeats keep flowing, data-path requests time out.

## The agent: tree search over tools

The agent consumes the decode JSON and detects failed procedures mechanically — an explicit reject carrying a cause, or a partial flow whose terminal message never arrived. For each, it runs a LATS search: Monte Carlo tree search over tool actions. Per node, two of the steps are the LLM (gpt-oss-120b via Groq) and three are code:

- **expand (LLM)** proposes actions: `inspect flow:1`, `spec "cause #21"`, `inspect kpis`…
- **execute (code)** dispatches them deterministically: flow inspection, spec retrieval over a local embedding index of TS 24.501 / 38.413 / 29.244 (pinned 19.x), topology inference, episodic-memory lookups, and `finalize`
- **evaluate (LLM)** scores the trajectory — reward, status, reflection
- **backprop + UCB1 selection (code)** value the nodes and pick the next branch; a search runs at most 10 rollouts

I chose LATS over a single free-form LLM call for one reason: tree search scores every trajectory as it goes, and that scoring is what a grounding mechanism can police. A one-shot prompt can only be checked after the fact; a search can be checked at every step.

A real run, on a lab capture where UE1 was seeded with the wrong Ki. Rollout 1, three proposals:

```
inspect flow:1    → reward=0.9  "…an authentication synch failure (cause
                    #21) that triggered a registration reject with protocol
                    error (cause #111)…"
spec cause #21     → reward=0.2  "Only a spec lookup… yielding no concrete
                    evidence…"
inspect kpis       → reward=0.2  "…no direct evidence linking cause codes
                    #21 or #111 to a specific root-cause…"
```

UCB1 picks the inspect branch. Rollout 2, the model proposes `finalize` with a structured episode: `incident_type: auth_failure`, a narrative, and two citations with timestamps. This is where the design earns its keep.

## The completeness bar

A node completes only when a `finalize` action produces an Episode that validates *and* grounds — enforced in code, regardless of what the evaluate step thinks:

1. The JSON parses and validates against a Pydantic schema: one of six incident types, a non-empty narrative, at least one cited evidence item.
2. Every citation must match the decode: a cited `(message, ts)` must hit a decoded message within 0.5 ms, and a cited cause must equal the decoded cause.

```
finalize accepted: hypothesis grounded in 2 evidence item(s).
```

The LLM can label a trajectory "complete" all it likes; nothing exits the search without a grounded finalize. A hallucinated citation — a plausible message name with a made-up timestamp, a cause code off by one — is rejected mechanically, and the expected schema is echoed back so the model can retry. In this run the grounded episode scored 1.0 and the search exited after two rollouts.

> My design rule: the LLM decides what to try and how promising it looks; the code decides what is true.

## Memory: the next search starts warm

The accepted episode is consolidated — CoALA-style, post-hoc — into an append-only JSONL store, exactly once per capture. Before the next search begins, code retrieves relevant past episodes with a deterministic score (3 points per shared cause code, 1 per shared message name, 2 for the same procedure) and injects the top matches into the search objective as *context*, behind an explicit guard: `cited_evidence` must still cite messages decoded in *this* capture.

Memory is context, never evidence. I made retrieval a local JSONL read with plain set arithmetic — no vector DB, no embedding call — partly for cost and reproducibility, and partly because at this store size structured lookup beats embedding similarity anyway.

## Judged by a different model

The eval harness replays the six labeled fixtures and scores each hypothesis two ways. `type_accuracy`: does the `incident_type` match the fixture label? `diagnosis_quality`: four 0–1 dimensions — Accuracy, Specificity, Evidence, Causality — scored by a judge model deliberately distinct from the generator (qwen3.6-27b vs gpt-oss-120b, both on Groq). The judge sees the hypothesis plus a brief of the decoded flow, never the ground-truth label, so Accuracy means "no invented facts" rather than "agrees with the label" — that second thing is what `type_accuracy` is for. The judge is a different model family on purpose: a model grading its own output is a rubber stamp.

The auth_failure run above was judged 4 × 1.0:

```json
{"scores": {"accuracy": 1.0, "specificity": 1.0, "evidence": 1.0, "causality": 1.0},
 "comment": "…the hypothesis precisely maps the authentication synchronization
             failure to the registration reject with correct cause codes and
             timestamps."}
```

Targets: `type_accuracy` ≥ 5/6 and `diagnosis_quality` ≥ 0.7. The two suites carry 123 pytest tests between them, and not one calls an LLM API — evals run explicitly, because every run costs real Groq calls.

## Who decides what

| Decision | Made by | Notes |
|---|---|---|
| Which flows are incidents | code | fixed wire-shape signatures |
| Which actions to propose | LLM | gpt-oss-120b, free-form |
| What an action *means* | code | deterministic dispatch |
| How promising a trajectory looks | LLM | advisory score only |
| Which branch to expand next | code | UCB1, C=1.4 |
| Whether cited evidence is real | code | message + ts (0.5 ms) + cause match |
| What gets remembered | code | consolidation, deduped |
| Whether the hypothesis is good (eval) | LLM | a different model family |

## What I haven't done yet

- **Real-cipher decryption.** The lab's AMF selects 5G-EA0 (null cipher), so protected NAS payloads are plaintext behind their MAC. CryptoMobile-based decryption is deferred; today a real cipher degrades to an honest `unparsed`, not a wrong parse.
- **A streaming monitor.** The agent triages a captured failure; it isn't a live detector.
- **More failure shapes.** The six incident types map one-to-one to the six lab scenarios; I add a category only when a real capture demands one.
- **Cheaper experiments.** Every search and every judge call is a real Groq API call, so the eval harness checkpoints after each fixture and resumes.
- **A bigger eval corpus.** Six shapes in one lab network — real, all labeled, but small.

## Read more

- **Repo** — [github.com/AdrianDonohoe/5G_PCAP](https://github.com/AdrianDonohoe/5G_PCAP)
- **One invocation, decision by decision** — [`triage/docs/invocation-walkthrough.md`](https://github.com/AdrianDonohoe/5G_PCAP/blob/master/triage/docs/invocation-walkthrough.md), with a rendered diagram of the whole flow
- **The reasoning** — [ADR: LATS + CoALA](https://github.com/AdrianDonohoe/5G_PCAP/blob/master/triage/docs/adr/0001-lats-coala-triage-agent.md) and the implementation-choices ADR
