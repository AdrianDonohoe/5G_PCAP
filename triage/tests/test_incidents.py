"""detect_incidents tests against the sandbox fixtures' real wire shapes
(no models, no network — synthetic n2/sbi dicts only)."""

from triage.incidents import detect_incidents, detect_sbi_incidents


def msg(ts, nas="", inner="", ngap="", cause=None):
    m = {"ts": ts}
    if ngap:
        m["ngap"] = ngap
    if nas:
        m["nas"] = nas
    if inner:
        m["nas_inner"] = inner
    if cause:
        m["nas_cause"] = cause
    return m


def flow(fid, messages=(), procedures=(), partial=False):
    return {"flow_id": fid, "messages": messages, "procedures": procedures,
            "partial": partial}


def proc(kind, outcome, start, end):
    return {"kind": kind, "outcome": outcome, "start_msg": start,
            "end_msg": end}


def test_reject_procedure_detected():
    # registration_reject / auth_failure: a registration reject record
    n2 = {"flows": [flow(2, procedures=[
        proc("registration", "reject", "5GMMRegistrationRequest",
             "5GMMRegistrationReject")])]}
    incidents = detect_incidents(n2)
    assert len(incidents) == 1
    assert incidents[0] == {"plane": "n2", "flow_id": 2,
                            "procedure": "Registration",
                            "shape": "explicit reject"}


def test_reject_procedure_with_cause_detail():
    # auth_failure carries #21 and #111 in the same flow
    n2 = {"flows": [flow(1, messages=[
        msg(1.0, nas="5GMMAuthenticationFailure", cause={"code": 21}),
        msg(2.0, inner="5GMMRegistrationReject", cause={"code": 111})],
        procedures=[proc("registration", "reject", "5GMMRegistrationRequest",
                         "5GMMRegistrationReject")])]}
    incidents = detect_incidents(n2)
    assert len(incidents) == 1
    assert incidents[0]["detail"] == "cause code(s) observed: #21, #111"


def test_status_cause_detected_despite_accept_procedures():
    # pdu_session_reject_slice: NGAP procedure records all read accept;
    # the failure is 5GMM STATUS #91 on the second PDU session
    n2 = {"flows": [flow(2, messages=[
        msg(1.0, nas="5GMMRegistrationRequest"),
        msg(2.0, inner="5GSMPDUSessionEstabRequest"),
        msg(3.0, inner="5GMMStatus", cause={"code": 91})],
        procedures=[proc("registration", "accept", "5GMMRegistrationRequest",
                         "5GMMRegistrationAccept"),
                    proc("pdu_session_est", "accept",
                         "PDUSessionResourceSetupRequest",
                         "PDUSessionResourceSetupResponse")])]}
    incidents = detect_incidents(n2)
    assert len(incidents) == 1
    assert incidents[0]["flow_id"] == 2
    assert incidents[0]["procedure"] == "PDU Session"
    assert incidents[0]["shape"] == "explicit reject"
    assert incidents[0]["detail"] == "cause code(s) observed: #91"


def test_request_echo_cause_is_timeout():
    # pdu_session_timeout: the SMF blackhole echoes the UE's request back
    # with #90 — no reject message, no failed procedure record
    n2 = {"flows": [flow(1, messages=[
        msg(1.0, nas="5GMMRegistrationRequest"),
        msg(2.0, inner="5GSMPDUSessionEstabRequest", cause={"code": 90}),
        msg(13.0, inner="5GSMPDUSessionEstabRequest", cause={"code": 90})],
        procedures=[proc("registration", "accept", "5GMMRegistrationRequest",
                         "5GMMRegistrationAccept")])]}
    incidents = detect_incidents(n2)
    assert len(incidents) == 1
    assert incidents[0]["procedure"] == "PDU Session"
    assert incidents[0]["shape"] == "no terminal message (timeout)"
    assert incidents[0]["detail"] == "cause code(s) observed: #90"


def test_lone_request_without_procedures_is_timeout():
    # registration_timeout: the paused AMF never answers — the flow holds a
    # single RegistrationRequest, no procedure records, partial=False
    n2 = {"flows": [flow(1, messages=[msg(1.0, nas="5GMMRegistrationRequest")])]}
    incidents = detect_incidents(n2)
    assert len(incidents) == 1
    assert incidents[0] == {"plane": "n2", "flow_id": 1,
                            "procedure": "Registration",
                            "shape": "no terminal message (timeout)"}


def test_partial_flow_is_timeout_incident():
    n2 = {"flows": [flow(1, messages=[msg(1.0, nas="5GMMRegistrationRequest")],
                         partial=True)]}
    incidents = detect_incidents(n2)
    assert len(incidents) == 1
    assert incidents[0]["shape"] == "no terminal message (timeout)"


def test_golden_flow_skipped():
    n2 = {"flows": [flow(1, messages=[
        msg(1.0, nas="5GMMRegistrationRequest"),
        msg(2.0, inner="5GMMRegistrationAccept")],
        procedures=[proc("registration", "accept", "5GMMRegistrationRequest",
                         "5GMMRegistrationAccept")])]}
    assert detect_incidents(n2) == []


def test_unknown_outcome_is_not_a_failure():
    n2 = {"flows": [flow(1, procedures=[
        proc("registration", "unknown", "5GMMRegistrationRequest", "")])]}
    assert detect_incidents(n2) == []


def test_multi_flow_mix_reports_only_failures():
    n2 = {"flows": [
        flow(1, procedures=[proc("registration", "accept",
                                 "5GMMRegistrationRequest",
                                 "5GMMRegistrationAccept")]),
        flow(2, procedures=[proc("pdu_session_est", "reject",
                                 "5GSMPDUSessionEstabRequest",
                                 "5GSMPDUSessionEstabReject")])]}
    incidents = detect_incidents(n2)
    assert [i["flow_id"] for i in incidents] == [2]
    assert incidents[0]["procedure"] == "PDU Session"


def test_unknown_procedure_kind_keeps_its_name():
    n2 = {"flows": [flow(1, procedures=[
        proc("handover", "reject", "HandoverRequired", "HandoverFailure")])]}
    assert detect_incidents(n2)[0]["procedure"] == "Handover"


def test_empty_flow_skipped():
    assert detect_incidents({"flows": [flow(1)]}) == []
    assert detect_incidents({}) == []


def sbi_proc(kind, outcome, status=None):
    p = {"kind": kind, "outcome": outcome}
    if status is not None:
        p["status"] = status
    return p


def test_sbi_reject_detected():
    # sbi_nssf_reject: the NSSelection consult comes back 403
    sbi = {"procedures": [
        sbi_proc("Nnrf_NFDiscovery", "accept", 200),
        sbi_proc("Nnssf_NSSelection", "reject", 403)]}
    incidents = detect_sbi_incidents(sbi)
    assert incidents == [{"plane": "sbi", "flow_id": None,
                          "procedure": "Nnssf_NSSelection",
                          "shape": "explicit reject",
                          "detail": "SBI status code(s) observed: 403"}]


def test_sbi_timeout_detected():
    # sbi_udm_timeout: the AUSF's Nudm_UEAuthentication is never answered
    sbi = {"procedures": [sbi_proc("Nudm_UEAuthentication", "timeout")]}
    incidents = detect_sbi_incidents(sbi)
    assert incidents == [{"plane": "sbi", "flow_id": None,
                          "procedure": "Nudm_UEAuthentication",
                          "shape": "no terminal message (timeout)"}]


def test_sbi_accept_procedures_skipped():
    assert detect_sbi_incidents(
        {"procedures": [sbi_proc("Nudm_SDM", "accept", 200)]}) == []
    assert detect_sbi_incidents({}) == []
