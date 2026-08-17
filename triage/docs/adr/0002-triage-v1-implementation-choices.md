# Triage v1: model, corpus, memory, and invocation choices

ADR-0001 accepted the LATS+CoALA architecture but explicitly deferred model,
observability, and several implementation-shape questions. This records
those, worked out together since they determine what triage's first
implementation actually looks like.

## Status

accepted

(Amended 2026-08-14 after sandbox feasibility verification: the
failure-injection mechanism below was generalized — the two *timeout* shapes
are injected by `docker pause`, not config overrides, and
`pdu_session_reject_other` needs a seed variant to produce a wire shape
distinct from the slice case. Amended again 2026-08-17 once all six scenario
fixtures were generated and decoded: several designed wire shapes are not what
Open5GS 2.8.0 actually emits, and one injection is impossible as designed —
see the failure-injection mechanism section.)

## Considered Options

**Model** — the `dspy_lats.py` reference targets Ollama-cloud-hosted
`gpt-oss:120b`. Chose the same model, `gpt-oss:120b`, but served via Groq's
API instead: same model quality, simpler dependency (one `GROQ_API_KEY`, no
local Ollama daemon to install/run on the sandbox VM). DSPy's LM abstraction
means this stays swappable.

**Observability** — the reference wires up MLflow for every run. Dropped for
v1: tracing helps debug a misbehaving search, but isn't needed to build one;
adding it back later (MLflow or otherwise) costs nothing once there's an
actual search to debug.

**Invocation** — a `5gcap triage` subcommand vs. a separate `triage` CLI.
Chose separate, matching the bounded-context split in `../CONTEXT-MAP.md`:
folding it into `5gcap`'s CLI would couple a deterministic, dependency-free
tool to an LLM/RAG/memory-store dependency it explicitly doesn't have.

**Package layout** — mirrors `5gcap`'s structure (own `pyproject.toml`,
`uv`-managed venv, `triage/triage/` package, `triage/tests/`) rather than
starting script-first like the reference. The separate-CLI decision already
requires a real entry point, so there's no looser starting point that avoids
an eventual migration.

**3GPP spec corpus** — fetched directly from 3GPP's own document repository
(TS 24.501 for NAS-5G cause codes, TS 38.413 for NGAP, TS 29.244 for PFCP —
the specs `5gcap` itself decodes against) and chunked locally, rather than an
existing public dataset of unknown provenance/currency. Retrieved via a
local embedding-based vector index: the corpus is small and static, but its
content is dense technical prose (a query like "why would authentication
fail" needs to match phrasing like "MAC verification failure"), so semantic
retrieval earns its complexity here even though episodic memory doesn't.

**Episodic memory backend** — a local JSON/file store, not a vector DB.
Unlike the spec corpus, what gates this is volume, not content density: v1
is single-machine and eval-driven, with too few Episodes for semantic
retrieval to outperform simple structured lookup (by `incident_type`, by
cited message type).

**NAS confidentiality in the sandbox** — the core's ciphering order starts
with `NEA0` (null cipher, `amf.yaml`), so the sandbox emits integrity-protected
but unencrypted NAS. Chosen over wiring the subscriber K/OPc into a
CryptoMobile decrypt step: the decoder still exercises
security-header handling, SMC algorithm capture, and inner-plaintext message
decode, while the capture pipeline keeps zero cryptographic dependencies.
Consequence: a real-world NEA1/NEA2 capture would decode only up to the
security header until CryptoMobile is added later.

**Failure-injection mechanism** — `sandbox/capture.sh` gains a `--scenario`
flag that applies a per-scenario override to UE1 only (wrong Ki for
`auth_failure`, a second PDU session on SST 2 for
`pdu_session_reject_slice`, etc.), reusing the existing UE configs rather than
a full parallel set. A scenario is an override plus optional hooks, not just
a field override: the two *timeout* shapes aren't expressible as config
fields; `registration_timeout` is `docker pause` of the AMF with a
fixed-duration capture, and `pdu_session_reject_other` needs a seed variant (a
DNN subscribed in UDM but absent from SMF). Ground truth attaches as a sibling
`<name>.label.json` next to the generated fixture, not a central manifest —
keeps every fixture's label colocated and never out of sync, and leaves the
golden-path (no `--scenario`) fixtures and their tests untouched.

The 2026-08-17 fixture-generation pass surfaced three facts that reshaped the
wire shapes, now documented as ground truth in `sandbox/README.md`:

- **`docker pause` of the SMF cannot produce a hang.** The NRF de-registers a
  heartbeat-less NF within one heartbeat interval (~10 s), which silently
  empties the AMF's discovery cache — the AMF answers the PDU request with an
  *instant* 5GMM #90 instead of hanging. `pdu_session_timeout` instead
  blackholes the SMF's SBI port (port 7777) from inside the SMF's own netns
  (the smf service runs with `cap_add: NET_ADMIN`): heartbeats keep the NRF
  registration alive while sm-context creates hang.
- **Open5GS hardcodes the AMF's SBI deadline to 11 s** (`time.message.duration`
  defaults to 10 s, deadline = duration + 1 s; the AMF never parses the key —
  only the NSSF does). The hang therefore ends in 5GMM #90 ("Payload was not
  forwarded"), with the AMF echoing the UE's request back in a DL NAS
  transport, and the UE re-attempting. The delay itself is the triage
  signature distinguishing this from an instant discovery-cache #90.
- **The textbook causes aren't what Open5GS emits**: wrong Ki produces SYNCH
  FAILURE #21 then REGISTRATION REJECT #111 (not AUTHENTICATION REJECT #20),
  and the UDM-only DNN produces 5GSM REJECT #67 (not #27). The slice case
  (`pdu_session_reject_slice`) is a two-session UE1 config so the capture
  carries both a golden SST 1 PDU accept and the 5GMM STATUS #91 on SST 2 in
  the same flow.

**Eval harness placement** — `triage/evals/`, run explicitly, not inside
`triage/tests/`'s default `pytest` run. `type_accuracy` and
`diagnosis_quality` cost real Groq API calls per invocation; nobody should
pay that latency/cost just from running the test suite, consistent with
`capture.sh` itself staying local/on-demand rather than CI-wired.

## Consequences

- `sandbox/`'s per-UE config files become the injection point for failure
  scenarios: each `incident_type` maps to one UE1 override plus optional
  seed/pause/blackhole hooks, documented alongside the config rather than as
  separate scenario files.
- `triage/`'s `pyproject.toml` needs `GROQ_API_KEY` documented as a required
  environment variable — there's no local-model fallback in v1.
- The 3GPP spec fetch is a one-time (or infrequent, on spec-version-bump)
  local corpus-build step, not part of every triage invocation.
