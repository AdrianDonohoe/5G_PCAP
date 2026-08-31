---
slug: nas-38-restart-smf
title: Restart the SMF when PDU session establishment fails with NAS cause 38
procedure: ""
added: 2026-08-29
symptoms:
  flow_id: 1
steps:
  - "Confirm the reject evidence: 5GSMPDUSessionEstabReject with nas_cause 38 (Network failure)."
  - "Restart the smf service to clear the faulty internal state that is generating the rejects."
  - "Re-run the capture scenario and check procedure_success_rate returns to the Golden baseline."
resolution:
  action: restart_nf
  args:
    nf: smf
---

# Restart the SMF on NAS cause 38 rejects

Derived from the committed sample incident record
(`docs/sample-incident-record.md`): the KPI detector reported
procedure_success_rate collapsed below the Golden baseline while every
session establishment ended in `5GSMPDUSessionEstabReject` with
nas_cause 38 (Network failure); the approved proposal was
`restart_nf {"nf": "smf"}`. The steps above are the record's narrative.
The args stay literal — KPI evidence carries only `flow_id` keys, so a
`{nf}` placeholder could never bind.
