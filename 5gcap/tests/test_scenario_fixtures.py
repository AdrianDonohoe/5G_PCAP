"""Failure-injection scenario fixtures from sandbox/capture.sh --scenario.

Each fixture applies a per-scenario failure to UE1 only; UE2/UE3 stay golden
when present. These decode through the same pipeline as the golden sandbox
capture, so assertions check the wire shapes documented in sandbox/README.md
against the sibling <name>.label.json ground-truth labels.
"""

import json
from pathlib import Path

from fivegcap.capture import read_capture
from fivegcap.flow import build_flows
from fivegcap.ngap import decode as ngap_decode

FIXTURES = Path(__file__).parent / "fixtures"

SCENARIOS = [
    "auth_failure",
    "registration_reject",
    "registration_timeout",
    "pdu_session_reject_slice",
    "pdu_session_reject_other",
    "pdu_session_timeout",
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
