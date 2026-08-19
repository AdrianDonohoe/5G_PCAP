# Context Map

## Contexts

- [5gcap](./CONTEXT.md) — deterministic, offline decoding of NGAP/NAS, PFCP, and SBI (HTTP/2) captures into Flows, Procedures, and KPIs. No network access, no LLM dependency, fully reproducible run-to-run.
- [triage](./triage/CONTEXT.md) — LLM-agent root-cause hypothesis generation for failed Registration/PDU-session Procedures, SBI service transactions, and N4 (PFCP) session-management procedures. Non-deterministic, depends on an LLM, a 3GPP-spec RAG index, and an episodic memory store.

Shared, cross-cutting infrastructure not owned by either context:

- [`sandbox/`](./sandbox/) — Open5GS + UERANSIM lab. Generates real captures for 5gcap's own fixtures, and (once extended) failure-injection scenarios with labeled ground truth for triage's evals.

## Relationships

- **triage → 5gcap**: triage consumes 5gcap's decode output (Flows, Procedures, decoded messages/IEs) as its evidentiary substrate; it does not re-implement or bypass decoding.
- **triage → sandbox**: triage's eval harness consumes sandbox failure-injection fixtures and their labeled ground-truth `incident_type` to score `type_accuracy` and `diagnosis_quality`.
- **5gcap → sandbox**: 5gcap's test suite consumes sandbox-generated captures (`sandbox_n2.pcap`, `sandbox_n4.pcap`) as fixtures, alongside its third-party-sourced ones.
