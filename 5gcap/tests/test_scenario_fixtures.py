"""Failure-injection scenario fixtures from sandbox/capture.sh --scenario.

Each fixture applies a per-scenario failure to UE1 only; UE2/UE3 stay golden
when present. These decode through the same pipeline as the golden sandbox
capture, so assertions check the wire shapes documented in sandbox/README.md
against the sibling <name>.label.json ground-truth labels.
"""

import json
from pathlib import Path

import pytest

from fivegcap.capture import read_capture, read_pfcp_capture
from fivegcap.cli import analyze
from fivegcap.flow import build_flows
from fivegcap.ngap import decode as ngap_decode
from fivegcap.pfcp import decode as pfcp_decode
from fivegcap.pfcp import pair_procedures as pair_pfcp_procedures
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


# N4-plane scenario: its pcaps arrive with the sandbox run
# (sandbox/capture.sh), so this test stays skipped until then. Wire shapes
# below are the source-verified expectations; tighten after the live run.

def _n4_procedures(scenario):
    raw = read_pfcp_capture(str(FIXTURES / f"{scenario}_n4.pcap"))
    msgs = [pfcp_decode(m.ts, m.data, m.src_ip, m.dst_ip, m.src_port,
                        m.dst_port)
            for m in raw]
    procedures, _ = pair_pfcp_procedures(msgs)
    return procedures, msgs


@pytest.mark.skipif(
    not (FIXTURES / "n4_upf_timeout_n4.pcap").exists(),
    reason="N4 pcaps arrive with the sandbox run (sandbox/capture.sh)")
def test_n4_upf_timeout():
    label = json.loads((FIXTURES / "n4_upf_timeout.label.json").read_text())
    assert label == {"incident_type": "n4_upf_timeout",
                     "scenario": "n4_upf_timeout"}
    # N4: the blackholed UPF never answers the SMF's Session Establishment
    # Requests. Open5GS retransmits at 2.5 s intervals but gives up ~7.5 s
    # after the first send (live-verified: the give-up pre-empts the 3rd
    # retransmit), so each UE attempt leaves a 3-request burst under one
    # seq -- kept as distinct messages (the burst is the timeout's physical
    # signature) but pairing as one unanswered request / one timeout
    # procedure anchored at the first send. The association setup retries
    # that start after the first missed heartbeat are maintenance traffic,
    # never incidents. Both nodes run independent seq counters, so the
    # pairing must be direction-aware or the counters' collisions produce
    # cross-type pairs.
    procedures, msgs = _n4_procedures("n4_upf_timeout")
    timeouts = [p for p in procedures
                if p.kind == "session_establishment"
                and p.outcome == "timeout"]
    assert timeouts, "the blackholed UPF must leave establishment requests unanswered"
    reqs = [m for m in msgs
            if m.name == "PFCP Session Establishment Request"]
    bursts = {}
    for m in reqs:
        bursts[m.seq] = bursts.get(m.seq, 0) + 1
    assert len(bursts) == len(timeouts), \
        "each timeout procedure must anchor one request seq"
    assert max(bursts.values()) >= 3, \
        "at least one attempt must show its full 3-request retransmit burst"
    assert any(p.kind == "association_setup" and p.outcome == "timeout"
               for p in procedures), \
        "the UPF's silence must also strand the association keepalive"
    # N2: registration completes; the PDU session establishment times out on
    # N4 and the AMF rejects with 5GSM cause #38 (Network failure) -- the
    # SMF's own ~7.5 s give-up, NOT 5GMM #90 (that is pdu_session_timeout's
    # AMF SBI deadline signature). Each early attempt carries the ~7.5 s
    # request-to-reject gap; after ~5 give-ups (~38 s, live-verified) the
    # SMF's PFCP state degrades and later attempts fail instantly without
    # ever reaching N4 (no establishment bursts serve them), so the fast
    # tail is expected and the all() assertion would be wrong.
    flows = _flows("n4_upf_timeout")
    assert flows, "the UE's registration must reach the AMF"
    delayed = []
    for f in flows:
        rej_ts = [m.ts for m, nas in f.messages if nas and nas.cause == 38]
        for m, nas in f.messages:
            if nas and nas.inner == "5GSMPDUSessionEstabRequest":
                later = [t for t in rej_ts if t > m.ts]
                if later:
                    delayed.append(min(later) - m.ts)
    assert delayed, "the N4 timeout must end in 5GSM REJECT #38"
    assert delayed[0] > 5.0, \
        "the first reject must arrive after the SMF's N4 give-up, not instantly"
    assert sum(1 for d in delayed if d > 5.0) >= 3, \
        "several attempts must show the ~7.5 s give-up before the SMF degrades"


# Merged-eval scenario (issue #14): the first fixture whose three planes
# are committed for ONE merged decode -- the eval harness's invocation --
# producing a joined SBI failure (AC2: >=1 SBI or N4 Incident with a
# non-None flow_id).

@pytest.mark.skipif(
    not (FIXTURES / "pdu_session_rsp_timeout_n2.pcap").exists(),
    reason="merged pcaps arrive with the sandbox run (sandbox/capture.sh)")
def test_pdu_session_rsp_timeout(tmp_path):
    label = json.loads(
        (FIXTURES / "pdu_session_rsp_timeout.label.json").read_text())
    assert label == {"incident_type": "pdu_session_rsp_timeout",
                     "scenario": "pdu_session_rsp_timeout"}
    merged = tmp_path / "pdu_session_rsp_timeout_merged.json"
    assert analyze(str(FIXTURES / "pdu_session_rsp_timeout_n2.pcap"),
                   str(merged),
                   sbi_path=str(FIXTURES / "pdu_session_rsp_timeout_sbi.pcap"),
                   n4_path=str(FIXTURES / "pdu_session_rsp_timeout_n4.pcap")) == 0
    data = json.loads(merged.read_text())
    # AC2: the merged decode carries an SBI failure joined to the flow. The
    # blackholed SMF *responses* leave every sm-context create unanswered
    # (the input-drop twin would kill the request before it is a message),
    # so the create's timeout procedure joins flow 1 via its body imsi-.
    sbi = data["sbi"]
    joined = [p for p in sbi["procedures"]
              if p.get("outcome") in ("reject", "timeout")
              and p.get("flow_id") is not None]
    assert joined, "the merged decode must carry a joined SBI failure"
    assert any(p["kind"] == "Nsmf_PDUSession" and p["outcome"] == "timeout"
               and p["flow_id"] == 1 for p in joined), \
        "the joined failure must be the unanswered sm-contexts create"
    flows = data["flows"]
    assert len(flows) == 1  # gnb+ue1 only
    f = flows[0]
    assert f["sbi_refs"], "the create must appear among the flow's SBI refs"
    assert [p["kind"] for p in f["procedures"]] == ["registration"], \
        "the PDU session must never complete"
    assert f["procedures"][0]["outcome"] == "accept"
    # N2: the AMF's ~11s SBI deadline bounces each PDU session request back
    # as 5GMM #90 (pdu_session_timeout's signature, the egress twin).
    req_ts = [m["ts"] for m in f["messages"]
              if m.get("nas_inner") == "5GSMPDUSessionEstabRequest"]
    bounce_ts = [m["ts"] for m in f["messages"]
                 if (m.get("nas_cause") or {}).get("code") == 90]
    assert req_ts and bounce_ts, "the bounce must carry 5GMM cause #90"
    assert min(bounce_ts) - min(req_ts) > 5.0, \
        "the #90 must arrive after the SBI deadline, not instantly"
    # N4: the SMF still reaches the UPF, so establishment completes under
    # the blackholed responses -- accepts, no session incident (the N2
    # SetupRequest never reaches the gNB, so the leg does not join).
    n4 = data["n4"]
    est = [p for p in n4["procedures"]
           if p["kind"] == "session_establishment"]
    assert est and all(p["outcome"] == "accept" for p in est), \
        "the UPF must answer the establishment (only the SBI leg is down)"
    assert not [p for p in n4["procedures"]
                if p["kind"].startswith("session_")
                and p["outcome"] in ("reject", "timeout")]
