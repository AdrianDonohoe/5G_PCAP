# 5G Control-Plane Capture Analysis

The domain language for the `5gcap` tool: decoding NGAP/NAS (N2), PFCP (N4), and SBI (HTTP/2 on TCP 7777) captures, mapping UE flows, and computing KPIs.

## Language

**Capture**:
One PCAP file recording a single interface over one time window.
_Avoid_: trace, dump, recording

**Flow**:
All N2 control-plane signaling belonging to one UE, associated across messages by NGAP UE IDs. N4 and SBI messages are standalone plane views, not part of any Flow; where a natural key exists on the wire (a GTP tunnel endpoint, a plaintext SUPI), they back-reference the Flow they correlate to — a link that exists or doesn't, never a guess.
_Avoid_: session, connection, stream

**Procedure**:
A protocol-defined exchange within a Flow, with a start message and a terminal outcome (e.g. registration, PDU session establishment). On the SBI plane: one HTTP request and its response, or a request never answered.
_Avoid_: transaction, dialog

**KPI**:
A numeric measure computed from Procedures in a Capture. Latency KPIs use the NAS terminal when it is plaintext, else the NGAP carrier of the terminal (attach: Registration Request, or `InitialUEMessage` → `InitialContextSetupRequest`; PDU session establishment: `PDUSessionResourceSetupRequest` → `Response`). Success rate counts every terminal outcome observed.
_Avoid_: metric, stat

**Partial Flow**:
A Flow whose start procedure is missing from the Capture. Decoded fully, but excluded from latency KPIs.
_Avoid_: incomplete flow, truncated flow
