<!--
Sample output over the sandbox `auth_failure` scenario capture
(5gcap/tests/fixtures/auth_failure.pcap), re-rendered 2026-08-20 via
`triage report --results` from a saved `triage analyze` run. The report
below is the writer's output verbatim except for this note, so visitors
can see a post-incident report without running the stack. Live runs need
GROQ_API_KEY; `triage report --results` re-renders any saved run offline.
-->

# Post-incident report — auth_failure

**Flow:** 1 — Registration, explicit reject
**Incident detail:** cause code(s) observed: #21, #111
**Hypothesis:** auth_failure (reward 0.95, 2 rollouts)

## Root cause
Authentication synchronization failure caused the registration to be rejected.

## Evidence
- [verified] 5GMMAuthenticationFailure over N2 from gNB (10.53.0.20) to AMF (10.53.0.11) @ 1786968770.968s — cause #21
- [verified] 5GMMRegistrationReject over N2 from AMF (10.53.0.11) to gNB (10.53.0.20) @ 1786968770.989s — cause #111

## Spec context
entity 5GMM cause #21 "Synch failure"
  defined_in: 5GMM cause IE (clause 9.11.3.2)
  co-mentioned: AUTHENTICATION FAILURE, AUTHENTICATION REJECT, AUTHENTICATION
                REQUEST, AUTHENTICATION RESPONSE, REGISTRATION REJECT,
                REGISTRATION REQUEST, SECURITY MODE COMMAND, SECURITY MODE
                REJECT … and 1 more

entity AUTHENTICATION FAILURE (message, from text)
  co-mentioned: 5GMM cause #11, 5GMM cause #20, 5GMM cause #21, 5GMM cause #23,
                5GMM cause #24, 5GMM cause #26, 5GMM cause #28, 5GMM cause #43 …
                and 33 more

entity 5GMM cause #111 "Protocol error, unspecified"
  defined_in: 5GMM cause IE (clause 9.11.3.2)
  co-mentioned: CONTROL PLANE SERVICE REQUEST, DEREGISTRATION REQUEST,
                Notification, Paging, REGISTRATION ACCEPT, REGISTRATION
                COMPLETE, REGISTRATION REJECT, REGISTRATION REQUEST … and 3 more

entity REGISTRATION REJECT (message, from text)
  co-mentioned: 5GMM cause #10, 5GMM cause #100, 5GMM cause #11, 5GMM cause #111,
                5GMM cause #12, 5GMM cause #13, 5GMM cause #15, 5GMM cause #20 …
                and 51 more


## Timeline (flow 1)
[1] 1786968770.955s  5GMMRegistrationRequest over N2 from gNB (10.53.0.20) to AMF (10.53.0.11)
[2] 1786968770.967s  5GMMAuthenticationRequest over N2 from AMF (10.53.0.11) to gNB (10.53.0.20)
[3] 1786968770.968s  5GMMAuthenticationFailure over N2 from gNB (10.53.0.20) to AMF (10.53.0.11)  cause #21 (Synch failure)
[4] 1786968770.989s  5GMMRegistrationReject over N2 from AMF (10.53.0.11) to gNB (10.53.0.20)  cause #111 (Protocol error, unspecified)
[5] 1786968770.991s  UEContextReleaseComplete over N2 from gNB (10.53.0.20) to AMF (10.53.0.11)

## Capture KPIs
attach_time_ms: 33.95835558573405 | pdu_session_time_ms: 104.17592525482178 | procedure_success_rate: 0.8 | procedure_successes: 4 | procedure_failures: 1

## Search path
[1] inspect flow:1 -> Flow 1 (RAN-UE-NGAP-ID 1, AMF-UE-NGAP-ID 1, complete):
[2] finalize {"incident_type": "auth_failure", "narrative": "Authentication synchronization failure caused the registration to be rejected.", "cited_evidence": [{"message": "5GMMAuthenticationFailure", "cause": 21, "ts": 1786968770.968}, {"message": "5GMMRegistrationReject", "cause": 111, "ts": 1786968770.989}]} -> finalize accepted: hypothesis grounded in 2 evidence item(s).

## Memory
new Episode written (auth_failure)
