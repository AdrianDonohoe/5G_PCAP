"""query_topology tests against the golden sandbox decode output.

fixtures/golden_n2.json and golden_n4.json are 5gcap's JSON exports of the
golden sandbox captures (../../5gcap/tests/fixtures/sandbox_n2.pcap and
sandbox_n4.pcap — 3 UEs, gNB + Open5GS core). Regenerate with, from the
5gcap project dir:

    uv run 5gcap analyze tests/fixtures/sandbox_n2.pcap \\
        --json ../triage/tests/fixtures/golden_n2.json
    uv run 5gcap analyze tests/fixtures/sandbox_n4.pcap \\
        --json ../triage/tests/fixtures/golden_n4.json

The sandbox IP plan pins the expected roles (AMF 10.53.0.11, SMF 10.53.0.12,
UPF 10.53.0.13); the gNB's IP is assigned by docker per run and shows up as
the InitialUEMessage source.
"""

import json
from pathlib import Path

from triage.topology import infer_topology, query_topology

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name):
    return json.loads((FIXTURES / name).read_text())


def _golden():
    return _load("golden_n2.json"), _load("golden_n4.json")


def _element(topo, role):
    return next(e for e in topo.elements if e.role == role)


def test_gnb_and_amf_roles_from_initial_ue_message():
    topo = infer_topology(*_golden())
    gNB = _element(topo, "gNB")
    amf = _element(topo, "AMF")
    assert gNB.ip == "10.53.0.20"  # InitialUEMessage source = the gNB
    assert amf.ip == "10.53.0.11"
    assert "InitialUEMessage" in gNB.evidence
    assert gNB.evidence == amf.evidence


def test_smf_and_upf_roles_fall_back_to_session_establishment():
    # The golden N4 capture starts after the core is up, so it contains no
    # PFCP Association Setup Request; the Session Establishment Request
    # (CP -> UP) must serve as the evidence instead.
    topo = infer_topology(*_golden())
    smf = _element(topo, "SMF")
    upf = _element(topo, "UPF")
    assert smf.ip == "10.53.0.12"
    assert upf.ip == "10.53.0.13"
    assert "Session Establishment Request" in smf.evidence
    assert "Association" not in smf.evidence
    assert smf.evidence == upf.evidence


def test_ues_summarized_from_flows():
    n2, _ = _golden()
    topo = infer_topology(n2)
    assert len(topo.ues) == 3
    ue1 = topo.ues[0]
    assert ue1.flow_id == 1
    assert ue1.ran_ue_ngap_id == 1 and ue1.amf_ue_ngap_id == 1
    assert not ue1.partial
    assert ue1.message_count == 12
    assert len(ue1.procedures) == 2
    assert all(p["outcome"] == "accept" for p in ue1.procedures)
    assert ue1.causes == []


def test_report_contains_roles_and_flows():
    report = query_topology(*_golden())
    assert "gNB  10.53.0.20" in report
    assert "AMF  10.53.0.11" in report
    assert "SMF  10.53.0.12" in report
    assert "UPF  10.53.0.13" in report
    assert "UEs (3 N2 flow(s)):" in report
    assert "Flow 1  RAN-UE-NGAP-ID=1  AMF-UE-NGAP-ID=1" in report


def test_partial_flow_and_deduped_causes_in_report():
    n2 = {
        "flows": [{
            "flow_id": 9,
            "ran_ue_ngap_id": 7,
            "amf_ue_ngap_id": 8,
            "partial": True,
            "messages": [
                {"ts": 1.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                 "ngap": "InitialUEMessage", "nas": "5GMMRegistrationRequest",
                 "nas_cause": None},
                {"ts": 2.0, "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1",
                 "ngap": "DownlinkNASTransport", "nas": "5GMMStatus",
                 "nas_cause": {"code": 90, "name": "Payload was not forwarded"}},
                {"ts": 3.0, "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1",
                 "ngap": "DownlinkNASTransport", "nas": "5GMMStatus",
                 "nas_cause": {"code": 90, "name": "Payload was not forwarded"}},
            ],
            "procedures": [],
        }],
        "unassociated": [],
    }
    topo = infer_topology(n2)
    ue = topo.ues[0]
    assert ue.partial and ue.message_count == 3
    assert ue.causes == [(90, "Payload was not forwarded")]  # deduped
    report = query_topology(n2)
    assert "Flow 9 [PARTIAL]" in report
    assert "cause #90 Payload was not forwarded" in report


def test_unknown_roles_when_no_message_carries_ips():
    n2 = {"flows": [{"flow_id": 1, "ran_ue_ngap_id": 1, "amf_ue_ngap_id": None,
                     "partial": True, "messages": [{"ts": 1.0, "ngap": "X",
                                                    "src_ip": None}],
                     "procedures": []}], "unassociated": []}
    topo = infer_topology(n2)
    assert _element(topo, "gNB").ip == "unknown"
    assert _element(topo, "AMF").ip == "unknown"
    assert "no IP-carrying N2 message" in _element(topo, "gNB").evidence


def test_unknown_smf_upf_without_n4():
    n2, _ = _golden()
    topo = infer_topology(n2, None)
    smf = _element(topo, "SMF")
    assert smf.ip == "unknown"
    assert "no N4 capture" in smf.evidence


def test_association_setup_preferred_over_session_establishment():
    n4 = {"messages": [
        {"ts": 1.0, "src_ip": "10.0.1.1", "dst_ip": "10.0.1.2",
         "name": "PFCP Heartbeat Request", "seid": None, "cause": None},
        {"ts": 2.0, "src_ip": "10.0.2.1", "dst_ip": "10.0.2.2",
         "name": "PFCP Session Establishment Request",
         "seid": 0, "cause": None},
        {"ts": 3.0, "src_ip": "10.0.3.1", "dst_ip": "10.0.3.2",
         "name": "PFCP Association Setup Request", "seid": None,
         "cause": None},
    ]}
    n2, _ = _golden()
    topo = infer_topology(n2, n4)
    smf = _element(topo, "SMF")
    assert smf.ip == "10.0.3.1"  # association setup's src, not 10.0.2.1
    assert _element(topo, "UPF").ip == "10.0.3.2"
    assert "Association Setup Request" in smf.evidence
