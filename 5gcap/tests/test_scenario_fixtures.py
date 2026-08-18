"""Failure-injection scenario fixtures from sandbox/capture.sh --scenario.

Each fixture applies a per-scenario failure to UE1 only; UE2/UE3 stay golden
when present. These decode through the same pipeline as the golden sandbox
capture, so assertions check the wire shapes documented in sandbox/README.md
against the sibling <name>.label.json ground-truth labels.
"""

import json
from pathlib import Path

import pytest

from fivegcap.capture import read_capture
from fivegcap.flow import build_flows
from fivegcap.ngap import decode as ngap_decode
from fivegcap.sbi import read_sbi_capture, pair_procedures

FIXTURES = Path(__file__).parent / "fixtures"

SCENARIOS = [
    "auth_failure",
    "registration_reject",
    "registration_timeout",
    "pdu_session_reject_slice",
    "pdu_session_reject_other",
    "pdu_session_timeout",
]

# SBI-plane scenarios: their pcaps arrive with the sandbox run
# (sandbox/capture.sh), so these tests stay skipped until then. Wire shapes
# below are the source-verified expectations; tighten after the live run.
SBI_SCENARIOS = [
    "sbi_udm_timeout",
    "sbi_nssf_reject",
]


def _flows(scenario):
    raw = read_capture(str(FIXTURES / f"{scenario}.pcap"))
    assert raw, f"{scenario}.pcap: no NGAP messages decoded"
    msgs = [ngap_decode(m.ts, m.assoc, m.stream, m.data, m.src_ip, m.dst_ip)
            for m in raw]
    flows, _ = build_flows(msgs)
    return flows


def _causes(flow):
    return [nas.cause for _, nas in flow.messages if nas and nas.cause is not None]


def _assert_golden(flow):
    assert [p.kind for p in flow.procedures] == ["registration", "pdu_session_est"]
    assert all(p.outcome == "accept" for p in flow.procedures)


def test_scenario_labels():
    for s in SCENARIOS:
        label = json.loads((FIXTURES / f"{s}.label.json").read_text())
        assert label == {"incident_type": s, "scenario": s}


def test_auth_failure():
    flows = _flows("auth_failure")
    assert len(flows) == 3
    failing = [f for f in flows if 21 in _causes(f)]
    assert len(failing) == 1, "exactly UE1 must carry SYNCH FAILURE #21"
    f = failing[0]
    # Open5GS answers the wrong-Ki UE with an AuthenticationFailure carrying
    # SYNCH failure #21 and then a REGISTRATION REJECT #111 (protocol error)
    # -- not the textbook AUTHENTICATION REJECT #20.
    assert 111 in _causes(f), "the synch failure must end in REGISTRATION REJECT #111"
    assert any(nas.name == "5GMMAuthenticationFailure"
               for _, nas in f.messages if nas)
    assert any(nas.name == "5GMMRegistrationReject"
               for _, nas in f.messages if nas)
    assert [p.kind for p in f.procedures] == ["registration"]
    assert f.procedures[0].outcome == "reject"
    for g in flows:
        if g is not f:
            _assert_golden(g)


def test_registration_reject():
    flows = _flows("registration_reject")
    assert len(flows) == 3
    failing = [f for f in flows if 7 in _causes(f)]
    assert len(failing) == 1, "exactly UE1 must carry REGISTRATION REJECT #7"
    f = failing[0]
    assert [p.kind for p in f.procedures] == ["registration"]
    assert f.procedures[0].outcome == "reject"
    for g in flows:
        if g is not f:
            _assert_golden(g)


def test_registration_timeout():
    flows = _flows("registration_timeout")
    # The paused AMF never answers, so the UE re-attempts registration on its
    # own timers: two flows (a new RAN-UE-NGAP-ID per attempt), each left open.
    assert len(flows) == 2
    for f in flows:
        requests = [nas for _, nas in f.messages
                    if nas and nas.name == "5GMMRegistrationRequest"]
        assert requests, "RegistrationRequest must be on the wire"
        assert f.procedures == []  # AMF frozen: no terminal outcome of any kind
        assert _causes(f) == []


def test_pdu_session_reject_slice():
    flows = _flows("pdu_session_reject_slice")
    assert len(flows) == 3
    failing = [f for f in flows if 91 in _causes(f)]
    assert len(failing) == 1, "exactly UE1 must carry 5GMM STATUS #91"
    f = failing[0]
    assert any(nas.inner == "5GMMStatus" for _, nas in f.messages if nas)
    # UE1's SST 1 session still completes (golden accept in the same flow);
    # only the SST 2 request is bounced with STATUS #91.
    _assert_golden(f)
    for g in flows:
        if g is not f:
            _assert_golden(g)


def test_pdu_session_reject_other():
    flows = _flows("pdu_session_reject_other")
    assert len(flows) == 3
    # The SMF has no "otherdnn": it answers 5GSM REJECT #67 (insufficient
    # resources for specific slice and DNN), not the textbook #27.
    failing = [f for f in flows if 67 in _causes(f)]
    assert len(failing) == 1, "exactly UE1 must carry 5GSM REJECT #67"
    f = failing[0]
    pdu = [p for p in f.procedures if p.kind == "pdu_session_est"]
    assert len(pdu) == 1
    assert pdu[0].outcome == "reject"
    for g in flows:
        if g is not f:
            _assert_golden(g)


def test_pdu_session_timeout():
    flows = _flows("pdu_session_timeout")
    assert len(flows) == 1  # gnb+ue1 only
    f = flows[0]
    # registration completes (SMF is not involved); the PDU request hangs
    assert [p.kind for p in f.procedures] == ["registration"]
    assert f.procedures[0].outcome == "accept"
    requests = [nas for _, nas in f.messages
                if nas and nas.inner == "5GSMPDUSessionEstabRequest"]
    assert requests, "PDU session request must be on the wire"
    # The blackholed SMF never answers: after Open5GS's hardcoded ~11s SBI
    # deadline the AMF echoes the request back with 5GMM cause #90 ("Payload
    # was not forwarded") and the UE re-attempts. The delay is the incident's
    # signature -- it must not arrive instantly.
    assert 90 in _causes(f), "the bounce must carry 5GMM cause #90"
    first_request = min(m.ts for m, nas in f.messages
                        if nas and nas.inner == "5GSMPDUSessionEstabRequest")
    first_bounce = min(m.ts for m, nas in f.messages if nas and nas.cause == 90)
    assert first_bounce - first_request > 5.0, \
        "the #90 must arrive after the SBI deadline, not instantly"


def _sbi_procedures(scenario):
    raw = read_sbi_capture(str(FIXTURES / f"{scenario}_sbi.pcap"))
    return pair_procedures(raw)


@pytest.mark.skipif(
    not (FIXTURES / "sbi_udm_timeout_sbi.pcap").exists(),
    reason="SBI pcaps arrive with the sandbox run (sandbox/capture.sh)")
def test_sbi_udm_timeout():
    label = json.loads((FIXTURES / "sbi_udm_timeout.label.json").read_text())
    assert label == {"incident_type": "sbi_udm_timeout",
                     "scenario": "sbi_udm_timeout"}
    # The blackholed UDM freezes AUSF's Nudm_UEAuthentication first; ANY
    # unanswered SBI request is the incident, so assert on timeouts rather
    # than a specific service name.
    procedures, unpaired = _sbi_procedures("sbi_udm_timeout")
    timeouts = [p for p in procedures if p.outcome == "timeout"]
    assert timeouts, "the blackholed UDM must leave SBI requests unanswered"
    assert unpaired >= 1
    # N2: the AMF can't obtain auth vectors, so after Open5GS's hardcoded
    # ~10s SBI deadline it rejects the registration with 5GMM cause #90
    # ("Payload was not forwarded" -- the AMF's gmm_cause_from_sbi(504)
    # mapping of the AUSF's gateway-timeout answer). The ~10s delay is the
    # incident's signature on N2; a later attempt may still be hanging when
    # the capture window ends, which is fine (the missing terminal message
    # is the expected outcome of a timeout scenario).
    flows = _flows("sbi_udm_timeout")
    assert flows, "registration attempts must reach the AMF"
    delayed = []
    for f in flows:
        req = min((m.ts for m, nas in f.messages
                   if nas and nas.name == "5GMMRegistrationRequest"),
                  default=None)
        rej = [m.ts for m, nas in f.messages if nas and nas.cause == 90]
        if req is not None and rej:
            delayed.append(min(rej) - req)
    assert delayed, "the hung auth chain must end in a registration reject #90"
    assert all(d > 5.0 for d in delayed), \
        "the reject must arrive after the SBI deadline, not instantly"


@pytest.mark.skipif(
    not (FIXTURES / "sbi_nssf_reject_sbi.pcap").exists(),
    reason="SBI pcaps arrive with the sandbox run (sandbox/capture.sh)")
def test_sbi_nssf_reject():
    label = json.loads((FIXTURES / "sbi_nssf_reject.label.json").read_text())
    assert label == {"incident_type": "sbi_nssf_reject",
                     "scenario": "sbi_nssf_reject"}
    # SBI: with the SMF profile deleted from the NRF, the AMF's
    # NRF-subscription-fed SMF cache is empty and it consults the NSSF,
    # which answers 403 "Cannot find NSI by S-NSSAI[SST:1 SD:0xffffff]"
    # (source-verified Open5GS v2.8.0, pinned from the live run).
    procedures, _ = _sbi_procedures("sbi_nssf_reject")
    rejects = [p for p in procedures
               if p.kind == "Nnssf_NSSelection" and p.outcome == "reject"]
    assert rejects, "the NSSF must reject the NSSelection consult"
    assert rejects[0].status == 403
    # N2: registration completes (no SMF involved); each PDU session consult
    # is bounced back as 5GMM STATUS. The STATUS cause IE is 147, not 403:
    # Open5GS passes the raw HTTP status straight into
    # nas_5gs_send_gmm_status(amf_ue, res_status) (src/amf/nnssf-handler.c)
    # whose parameter is uint8_t ogs_nas_5gmm_cause_t, so 403 (0x0193)
    # truncates to 0x93 = 147 on the wire (inner NAS "7e 00 64 93"). The 403
    # lives on the SBI plane, asserted above; 147 is not a defined 5GMM
    # cause (pycrate leaves its name None) -- it is the truncation artifact
    # itself.
    flows = _flows("sbi_nssf_reject")
    assert len(flows) == 1  # gnb+ue1 only
    f = flows[0]
    reg = [p for p in f.procedures if p.kind == "registration"]
    assert reg and reg[0].outcome == "accept"
    assert _causes(f) == [147, 147, 147], \
        "each PDU session consult must bounce as 5GMM STATUS with cause 147"
    assert any(nas.inner == "5GMMStatus" for _, nas in f.messages if nas)
