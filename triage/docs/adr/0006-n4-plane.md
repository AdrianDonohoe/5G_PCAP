# N4-plane triage: PFCP timeout outcome, session-set incidents, and the n4_upf_timeout scenario

The repo triaged two planes: N2 (NGAP/NAS) and SBI (HTTP/2). The N4 (PFCP)
plane was decoded by 5gcap from the start but never triaged — no incident
detection, no eval fixture, no failure-injection scenario. This ADR adds
the third plane end to end: a `timeout` procedure outcome plus numeric
cause export in the PFCP decoder, triage incident detection + LATS over
PFCP evidence, report rendering, an eval plane filter, and one sandbox
scenario (`n4_upf_timeout`) that pins the plane's one real failure shape.

## Status

accepted

## Considered Options

**Decoder outcome** — unanswered PFCP requests become `timeout` procedures
(mirroring the SBI decoder) vs. staying dangling. A request never answered
by capture end is a first-class failure, not an accident of the capture
window. `unpaired_requests` keeps its count semantics; the pairing contract
is untouched.

**Numeric cause export** — `to_pfcp_dict` procedures gain the numeric
`cause` alongside the existing `cause_name`. Triage reject detail ("PFCP
cause code(s) observed: N") and evidence grounding both need the number;
the name string alone would leave the two ints indistinguishable.

**Retransmit dedup** — keep the retry burst as distinct messages vs.
collapsing retransmissions. The t=0/2.5/5/7.5 s burst of four identical
Session Establishment Requests under one seq is the timeout's physical
signature — deleting it would delete the evidence. Seq-keyed pairing
already collapses the burst to one unpaired entry per attempt, so one
`timeout` procedure anchors each attempt's first send.

**Incident scope** — session-management procedures only (establishment /
modification / deletion / report). Heartbeat, association, and node-report
traffic is maintenance: listable and citable as Evidence, never an
Incident — otherwise every healthy capture would light up with heartbeat
incidents. Shape literals reused verbatim ("explicit reject" / "no
terminal message (timeout)"), so the search's timeout special-case keeps
working. N4 incidents carry `flow_id: None` — nothing in a PFCP message
correlates to an N2 flow — and cite the PFCP procedure name as
`procedure`.

**Type name** — `n4_upf_timeout` joins the closed incident_type set (eight
→ nine), one-to-one with the scenario labels. NF-scoped, consistent with
`sbi_udm_timeout`. `_procedure_of` maps it to "PDU Session" — the N4 view
of PDU session establishment — so the episodic-memory same-procedure bonus
fires for the one N4 failure shape that exists.

**Eval plane filter** — each fixture searches only its own plane's
incidents (the SBI pattern). Without it, `pdu_session_timeout`'s N4 view —
which legitimately shows unanswered PFCP traffic, since that injection
blackholes the SMF's SBI port and the N4 requests never leave it — would
be searched against an N2 label. The `n4_upf_timeout` fixture decodes a
second pcap and joins the run only once it exists (gated on the sandbox
captures).

**One scenario, not two** — `n4_upf_timeout` only. The two candidate
shapes failed fact-finding against Open5GS v2.8.0 sources: no config knob
makes the UPF answer session establishment with a non-accept cause (no
injectable PFCP reject), and a mid-session blackhole (heartbeat loss) has
no session-level wire signature — the SMF's `reselect_upf()` finds "No UPF
available" in a single-UPF core and tears nothing down, leaving only
unanswered heartbeats and association retries, which the session-set rule
excludes. This matches the CONTEXT.md gate: types are added only for real
failure shapes.

## The scenario mechanics

**`n4_upf_timeout`** — gNB up, blackhole the UPF's PFCP port from inside
its netns (`iptables -A INPUT -p udp --dport 8805 -j DROP`; the upf
service already runs with NET_ADMIN), UE registers and requests a PDU
session. The blackholed port leaves every SMF Session Establishment
Request unanswered: Open5GS retransmits 3× at 2.5 s intervals (t1 = 10 s /
4, source-verified), so each UE attempt leaves a 4-request burst under one
seq, then gives up ~10 s later and the AMF answers the UE with **PDU
SESSION ESTABLISHMENT REJECT, 5GSM cause #38 (Network failure)**. The
cause is #38, NOT 5GMM #90 — #90 is the AMF's own SBI deadline signature
in `pdu_session_timeout`; here the SMF's N4 give-up produces the reject,
and the SBI side shows a *successful* 201 sm-context create followed by
the N1N2 reject transfer — a clean differentiator between the two
timeouts. The UPF's SBI heartbeats keep flowing, so the NRF never purges
it; only the PFCP data path is dead, and association setup retries start
after the first missed heartbeat (~11 s) — maintenance traffic, never
incidents. Live-verified on the first sandbox run; if versions drift,
adjust fixture asserts, not the scenario.

## Consequences

- `5gcap analyze` N4 procedures gain a `timeout` outcome and numeric
  `cause`/`cause_name`; retransmits stay distinct messages.
- `triage analyze` detects N4 incidents; `triage report --n4 PATH` renders
  the N4 timeline with `-> no response` for unanswered requests (paired on
  the flipped (src, dst, seq) tuple). Evidence handles gain `n4:<i>`.
  `--flow N` filters N2 incidents only (N4 incidents have no flow_id).
- `sandbox/capture.sh` captures the N4 pcap on every run (the SBI
  precedent), not just the golden run; the scenario's blackhole rule is
  reverted in cleanup.
- The spec corpus is unchanged: PFCP procedure and cause queries already
  resolve against the committed TS 29.244 chunks.
- Eval targets become type_accuracy >= (n-1)/n (8/9 with all nine fixtures
  enabled) and diagnosis_quality >= 0.7, unchanged in spirit.
