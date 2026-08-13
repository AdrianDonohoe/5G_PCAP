# 5G Control-Plane Capture Analysis

The domain language for the `5gcap` tool: decoding NGAP/NAS (N2) and PFCP (N4) captures, mapping UE flows, and computing KPIs.

## Language

**Capture**:
One PCAP file recording a single interface over one time window.
_Avoid_: trace, dump, recording

**Flow**:
All N2/N4 control-plane signaling belonging to one UE, associated across messages by NGAP UE IDs.
_Avoid_: session, connection, stream

**Procedure**:
A protocol-defined exchange within a Flow, with a start message and a terminal outcome (e.g. registration, PDU session establishment).
_Avoid_: transaction, dialog

**KPI**:
A numeric measure computed from Procedures in a Capture. Latency KPIs use the NAS terminal when it is plaintext, else the NGAP carrier of the terminal (attach: Registration Request, or `InitialUEMessage` → `InitialContextSetupRequest`; PDU session establishment: `PDUSessionResourceSetupRequest` → `Response`). Success rate counts every terminal outcome observed.
_Avoid_: metric, stat

**Partial Flow**:
A Flow whose start procedure is missing from the Capture. Decoded fully, but excluded from latency KPIs.
_Avoid_: incomplete flow, truncated flow
