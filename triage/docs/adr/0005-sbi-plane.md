# SBI-plane triage: HTTP/2 decode, plane plumbing, and the 29.5xx dialect

The repo triaged two planes: N2 (NGAP/NAS) and N4 (PFCP). The sandbox's
Open5GS core also runs a full SBI plane — plaintext HTTP/2 (h2c) on TCP
7777 between the 10.53.0.x network functions — that was never captured or
decoded, and 5gcap's README declared it out of scope. This ADR adds the
third plane end to end: 5gcap SBI decode, triage incident detection + LATS
over SBI evidence, the TS 29.5xx spec-corpus dialect, report rendering, an
eval plane filter, and two new sandbox failure scenarios
(`sbi_udm_timeout`, `sbi_nssf_reject`) that pin the plane's two real
failure shapes.

## Status

accepted

## Considered Options

**Decode** — new 5gcap SBI decoder vs. leaving SBI out of scope. The
capture→decode→triage→report→eval loop earns its third plane because the
two new scenarios *are* SBI failures: a blackholed UDM and an NSSF 403 are
invisible on N2 alone, and the existing six scenarios gain visibility
evidence from unconditional SBI capture. Chose the full loop, mirroring
N2/N4.

**HTTP/2 framing** — the `h2` (hyper) library vs. scapy's contrib.http2.
Scapy's HTTP/2 contrib is a partial frame parser; `h2` is the reference
implementation and Open5GS's Node http2 stack compresses headers (HPACK),
which a frame-only parser never recovers. `h2` parses both directions with
HPACK state per direction; scapy stays for packet I/O. Rejected a
home-grown frame parser on the same grounds as the h2 choice: header
decompression is the hard part and `h2` already owns it.

**Export shape** — mirrors `to_pfcp_dict` exactly
(`messages`/`procedures`/`unpaired_requests`). Triage already traverses
that shape for N4, so the SBI plane gets identical traversal with zero new
machinery. Each message: `ts, src/dst ip+port, stream_id, direction
(request|response), method, path, status, body_len, service + name (the
spec service name Evidence cites), problem_title, problem_cause (from
ProblemDetails bodies), unparsed`. Procedures pair per (connection,
stream_id); a request never answered by capture end is a `timeout`
procedure and counts toward `unpaired_requests`.

**Incident shape** — the two existing wire-shape literals verbatim:
"explicit reject" (HTTP status >= 400) and "no terminal message (timeout)"
(unanswered request). These are plane-neutral properties, so the search's
timeout special-case keeps working. `sbi_udm_timeout` / `sbi_nssf_reject`
join the closed incident_type set (six → eight), one-to-one with the
scenario labels. SBI incidents carry `flow_id: None` — SBI messages are
not correlated to N2 flows — and cite the service name as `procedure`.

**Evidence schema** — unchanged. SBI evidence cites `message` = service
name, `cause = None`, `ts`; the HTTP status lives in the narrative prose
and the report timeline, not the EvidenceItem. The finalize template and
`grounded_evidence` match semantics stay untouched, and the report's
`cause=None` → no-cause-suffix rendering falls out for free.

**Spec corpus + dialect** — TS 29.500 (framework), 29.503 (UDM), 29.531
(NSSF) join the committed corpus (29.510 skipped: no scenario exercises
it). One deterministic SBI rule family, no LLM pass (ADR-0003), no cause
tables (HTTP statuses are not cause IEs):

1. Heading-derived: the 29.5xx headings that carry an N-name pattern
   ("Nudm_UEAuthentication Service API", "Get service operation of
   Nnssf_NSSelection service") yield message entities.
2. Body-derived, validated: body matches of the same pattern become
   entities only when the name or its family prefix (up to the first `_`)
   is in the heading-derived vocabulary — decoder aliases like `Nudm_SDM`
   enter, cross-family mentions like `Nsmf_PDUSession` in 29.500 do not.
3. The fixed entity "ProblemDetails" appears only when a "ProblemDetails"
   heading exists in the corpus (in 29.500 j70 it does not — the type
   moved to TS 29.571 — so the real graph omits it).

SBI messages are excluded from the co-mention scan: their dialect has no
cause/procedure peers, so they never form `co_mentioned` edges.

**Eval plane filter** — each fixture searches only its own plane's
incidents. Without it, `pdu_session_timeout`'s SBI view — which
legitimately shows an unanswered Nsmf_PDUSession request, since that
injection blackholes the SMF's 7777 — would be searched against an N2
label. The two sbi_* fixtures decode a second pcap and join the run only
once it exists (gated on the sandbox captures).

## The two scenario mechanics

**`sbi_udm_timeout`** — gNB up, blackhole the UDM's SBI port from inside
its netns (the `pdu_session_timeout` trick: an INPUT DROP on 7777, with
NET_ADMIN on the udm service), UE registers. Registration reaches the UDM
through the AUSF, so the auth chain hangs until the AMF's SBI deadline
(~10 s) and the capture holds the unanswered request. Pausing the UDM
container does NOT work: the AUSF fails fast on the broken connection and
the AMF rejects in 2-3 ms — no hang. The observable timeout is the AMF's
Nausf_UEAuthentication request (the AUSF→UDM hop never emits frames on
the blackholed port); detection accepts ANY unanswered SBI request — it
must not require a specific service. The fixture also carries two
Nausf_UEAuthentication 504s (the AUSF's gateway-timeout answers), the
same story as explicit rejects. On N2 the AMF rejects the registration
with 5GMM cause #90 ("Payload was not forwarded" — its
`gmm_cause_from_sbi(504)` mapping) exactly at the deadline (10.0 s
request-to-reject, live-verified); the UE retries and a later attempt is
still hanging when the capture window ends.

**`sbi_nssf_reject`** — a compound injection, because no single knob in
Open5GS produces a wire-visible NSSF reject: the AMF consults the NSSF
only when its SMF cache is empty (source-verified against Open5GS
v2.8.0). The cache is fed by NRF nf-status-notify subscriptions, not by
`/nnrf-disc/` discovery calls — none appear on the wire — so all three
legs are needed:

1. `db.nf_profiles.deleteMany({nfType:"SMF"})` — empties the cache via
   the NRF subscription.
2. `docker pause sandbox_smf` — keeps the SMF from
   heartbeat-re-registering its profile mid-capture.
3. Retarget the NSI in `nssf.yaml` to a slice nobody requests
   (`sst: 1` → `sst: 2`) + restart the NSSF — with no NSI mapping
   S-NSSAI 1, NSSelection answers 403 "Cannot find NSI by
   S-NSSAI[SST:1 SD:0xffffff]". Removing the `nsi:` entry does NOT work:
   the NSSF aborts at boot with "No nssf.nsi", and it requires at least
   one NSI entry to initialize.

Expected wire signature: registration accept → PDU session →
Nnssf_NSSelection GET 403 (one per slice-consult, ×2 per UE attempt) →
AMF → **5GMM STATUS with cause 147** to the UE (NOT registration reject
#62). The cause is 147, not 403: `nnssf-handler.c` passes the raw HTTP
status through `nas_5gs_send_gmm_status()`, whose parameter is
`uint8_t ogs_nas_5gmm_cause_t`, truncating 0x0193 to 0x93 on the wire
(inner NAS `7e 00 64 93`). Live-verified on the first sandbox run; if
versions drift, adjust fixture asserts, not the scenario. Cleanup:
unpause + restart the SMF (re-registers with the NRF), restore nssf.yaml +
restart the NSSF.

## Consequences

- `5gcap analyze` ladder becomes N2 → N4 → SBI; SBI decode is lenient
  like the rest of 5gcap (failures → `unparsed`, never fatal), and
  midstream-capture connections (tcpdump starts after the HTTP/2 preface)
  degrade to `unparsed`.
- `triage analyze --sbi PATH` / `triage report --sbi PATH`; `--flow N`
  filters N2 incidents only (SBI incidents have no flow_id). Evidence
  handles gain `sbi` / `sbi:<i>`.
- The corpus grows to six specs (~5000 chunks); the embedding index
  rebuilds once (one-time offline job) and the graph cache re-keys on the
  corpus sha. SBI report timelines pair requests to responses on the
  flipped connection tuple and render "-> no response" for unanswered
  requests.
- Golden SBI captures contain periodic NRF heartbeats — small all-accept
  procedures, harmless to detection and to the golden all-accept decode.
- Eval targets become type_accuracy >= (n-1)/n (7/8 with all eight
  fixtures enabled) and diagnosis_quality >= 0.7, unchanged in spirit.
