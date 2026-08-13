# 5G_PCAP

5G control-plane capture analysis: decode NGAP/NAS (N2) and PFCP (N4)
captures, map per-UE flows, and compute KPIs.

## Layout

- [`5gcap/`](5gcap/) — the analyzer itself (`5gcap analyze <file.pcap>`). See
  [`5gcap/README.md`](5gcap/README.md) for usage and v1 scope.
- [`sandbox/`](sandbox/) — local Open5GS + UERANSIM lab that generates real
  captures for `5gcap` to decode. See [`sandbox/README.md`](sandbox/README.md).
- [`CONTEXT.md`](CONTEXT.md) — domain glossary (Capture, Flow, Procedure,
  KPI, Partial Flow).
- [`docs/adr/`](docs/adr/) — architecture decision records.

## Development

```
cd 5gcap
uv sync
uv run pytest
```
