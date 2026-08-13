# Self-hosted Open5GS + UERANSIM sandbox for fixture generation

`5gcap`'s existing fixtures (`modem_testrun.pcap`, `5g_signaling_example.pcap`) are Open5GS+UERANSIM captures sourced from third parties — we have no way to generate more of them, or scenarios tailored to gaps in coverage. We're standing up a local sandbox that runs the same stack ourselves via Docker Compose, so we can generate our own Registration + PDU session establishment captures on demand, and use the running stack as an interactive lab.

## Status

accepted — **amended** (same session, first implementation fact-check): generating `sandbox_n4.pcap` surfaced that `5gcap` had no PFCP decoding at all — `fivegcap/` was NGAP-only end to end, despite the README and this ADR's own stack description treating PFCP-over-N4 as already in scope. Implemented `fivegcap/pfcp.py` (decode via `pycrate_mobile.TS29244_PFCP`, request/response pairing by PFCP sequence number) so `5gcap analyze` now handles a PFCP-only capture instead of hard-erroring. Reported as a standalone N4 message/procedure trace, not folded into the existing NGAP-scoped KPI vocabulary in `CONTEXT.md` — nothing in a PFCP message carries an NGAP UE ID, so there's no on-the-wire way to correlate it back to a Flow.

## Considered Options

- **Single long-lived stack (core + RAN together)**: simpler to operate, but a UE that's been running for a while and re-registers mid-capture risks producing a Partial Flow (missing its start message) — which `CONTEXT.md` explicitly excludes from latency KPIs. Rejected: it works against the fixture's whole purpose.
- **Full ephemeral stack (core + RAN torn down every run)**: guarantees clean captures, but re-provisions Open5GS's subscriber DB from scratch each time and kills the "interactive lab" purpose — nothing persists to come back and poke at.
- **Split lifecycle (chosen)**: Open5GS core stays long-lived with a persistent volume, subscribers seeded once via a version-controlled script (not the WebUI, so it survives the volume being wiped). UERANSIM (gNB + UEs) is ephemeral, recreated per capture run against the standing core — every run starts from a clean 5G-GUTI state, so every capture is guaranteed complete from the first message.
- **Merged multi-interface capture**: `5gcap` explicitly treats "one PCAP, one interface" as a Capture, and documents mixed-interface files as only getting a lenient warning-path decode — not the intended usage. We capture N2 and N4 separately instead, since they're already on distinct Docker bridges.

## Consequences

- Two separate Docker Compose projects (`sandbox/core/`, `sandbox/ran/`) joined by an external Docker network, rather than one compose file — keeps the capture script's blast radius limited to the RAN project it's allowed to tear down.
- The capture pipeline is local/on-demand only, not run in CI: nested Docker Compose with SCTP transport is a real source of CI flakiness for a project at this stage. Fixtures are regenerated locally and committed like any other fixture.
- Output is two fixed, deterministic filenames (`sandbox_n2.pcap`, `sandbox_n4.pcap`) overwritten each run and reviewed via `git diff`/`git status`, not timestamped/accumulated files.
- A new test file (following the existing one-hardcoded-fixture-per-test pattern) asserts the generated captures decode cleanly and produce expected KPIs, so the fixture doesn't silently bit-rot if `5gcap`'s decoding changes.
