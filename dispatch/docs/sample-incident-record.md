# Incident Record — inc-kpi-20a3050c

## Event

- Incident id: `inc-kpi-20a3050c`
- Detected at: 1788014212.511896
- Source: kpi
- Procedure: -
- Time window: 1788014158.482346 → 1788014212.511896

KPI degradation: procedure_success_rate 0.07142857142857142 below golden 1.0; pdu_session_time_ms 1744.261539899386 above twice golden 3.2886664072672525; reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13; reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13; reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13; reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13; reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13; reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13; reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13; reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13; reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13; reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13; reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13; reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13; reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13

## Correlation graph

- [0] pcap explicit reject: 5GSMPDUSessionEstabReject cause 38 (keys: flow_id=1) — cited: flow:1:13
- [1] pcap no terminal message (timeout): PFCP Session Establishment Request (keys: ) — cited: n4:18
- [2] pcap no terminal message (timeout): PFCP Session Establishment Request (keys: ) — cited: n4:18
- [3] pcap no terminal message (timeout): PFCP Session Establishment Request (keys: ) — cited: n4:18
- [4] pcap no terminal message (timeout): PFCP Session Establishment Request (keys: ) — cited: n4:18
- [5] kpi KPI deviation: procedure_success_rate 0.07142857142857142 below golden 1.0 (keys: ) — cited: kpi.procedure_success_rate=0.07142857142857142
- [6] kpi KPI deviation: pdu_session_time_ms 1744.261539899386 above twice golden 3.2886664072672525 (keys: ) — cited: kpi.pdu_session_time_ms=1744.261539899386
- [7] kpi reject message: reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13 (keys: flow_id=1) — cited: kpi.procedure_failures=13
- [8] kpi reject message: reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13 (keys: flow_id=1) — cited: kpi.procedure_failures=13
- [9] kpi reject message: reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13 (keys: flow_id=1) — cited: kpi.procedure_failures=13
- [10] kpi reject message: reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13 (keys: flow_id=1) — cited: kpi.procedure_failures=13
- [11] kpi reject message: reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13 (keys: flow_id=1) — cited: kpi.procedure_failures=13
- [12] kpi reject message: reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13 (keys: flow_id=1) — cited: kpi.procedure_failures=13
- [13] kpi reject message: reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13 (keys: flow_id=1) — cited: kpi.procedure_failures=13
- [14] kpi reject message: reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13 (keys: flow_id=1) — cited: kpi.procedure_failures=13
- [15] kpi reject message: reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13 (keys: flow_id=1) — cited: kpi.procedure_failures=13
- [16] kpi reject message: reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13 (keys: flow_id=1) — cited: kpi.procedure_failures=13
- [17] kpi reject message: reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13 (keys: flow_id=1) — cited: kpi.procedure_failures=13
- [18] kpi reject message: reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13 (keys: flow_id=1) — cited: kpi.procedure_failures=13
- [19] kpi reject message: reject message: 5GSMPDUSessionEstabReject nas_cause 38 (Network failure) — kpi.procedure_failures=13 (keys: flow_id=1) — cited: kpi.procedure_failures=13

- no links

## Root cause

The session establishment repeatedly failed due to NAS cause 38 indicating a network failure, as shown by explicit reject messages and KPI failures.

## Proposal

- Action: `restart_nf`
- Arguments: `{"nf": "smf"}`

Restarting the SMF clears the faulty internal state that is generating NAS cause 38 rejects, allowing PDU session establishment to succeed again.

Commands (template-rendered):

- docker compose --project-directory /path/to/5G_PCAP/sandbox/core restart smf

Proposal hash: `803c4324dbadc3bb18dc5b7aeb123ec6b4604b9473f31426c1045310fd4be13a`

## Approval status

Approval status: **pending**

## Execution log

- (empty)
