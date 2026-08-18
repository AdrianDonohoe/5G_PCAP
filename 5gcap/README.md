# 5gcap

5G control-plane PCAP analyzer: decodes NGAP/NAS (N2), PFCP (N4), and SBI (HTTP/2 on TCP 7777) captures, maps per-UE flows, and computes KPIs.

Domain language (Capture, Flow, Procedure, KPI, Partial Flow) is defined in [`../CONTEXT.md`](../CONTEXT.md). The packet-parsing stack decision is recorded in [`../docs/adr/0001-scapy-for-packet-parsing.md`](../docs/adr/0001-scapy-for-packet-parsing.md).

## Usage

```
5gcap analyze <file.pcap> [--json out.json]
```

Single pass: decodes procedures, prints a terminal trace, computes KPIs, optionally writes structured JSON. A PFCP-only (N4) or SBI-only capture is detected automatically and prints a message/procedure trace instead — KPIs (attach time, PDU session establishment time) are defined over the NGAP carrier only (see `../CONTEXT.md`), not N4 or SBI.

## Stack

- **pycrate** — ASN.1/CSN.1 decoding of NGAP, NAS-5G, PFCP (see ADR-0001)
- **scapy** — PCAP I/O and SCTP transport reassembly
- **h2** (hyper) — HTTP/2 framing + HPACK for the SBI plane (h2c on TCP 7777); scapy stays for packet I/O
- NAS security-protected payloads cannot be decrypted (`CryptoMobile` absent) — surfaced as `unparsed`

## v1 scope and limits

- Control plane only: NGAP/NAS over N2, PFCP over N4, SBI (HTTP/2) on TCP 7777. GTP-U user plane is out of scope.
- First procedures: Registration and PDU session establishment.
- **One interface per capture.** Mixed multi-interface files get a warning and lenient best-effort decode.
- **Capture size budget: ~100 MB** (pure-Python parsing).
- Decode is lenient: unknown IEs/messages are annotated `unparsed`, never fatal.
- KPIs: attach time, PDU session establishment time, procedure success rate. Modern 5G protects NAS terminal outcomes, so latency pairing uses the plaintext NAS terminal when visible and falls back to its NGAP carrier (`InitialUEMessage` → `InitialContextSetupRequest`; `PDUSessionResourceSetupRequest` → `Response`). Latency KPIs are computed on complete procedures only; partial flows are flagged. (CryptoMobile-based NAS decryption for lab captures is a planned opt-in enhancement, not v1.)

## Development

```
uv sync
uv run pytest
```
