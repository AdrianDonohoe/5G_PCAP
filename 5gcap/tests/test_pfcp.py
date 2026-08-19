"""PFCP (N4) decoder tests over synthetic UDP pcaps.

Offline by construction: the pcaps are built in tmp_path from pycrate-encoded
PFCP frames (the decoder under test is a passive reader of their wire bytes)
and wrpcap'd as Ethernet/IP/UDP packets on port 8805.
"""

from pycrate_mobile.TS29244_PFCP import (PFCPSessionEstablishmentReq,
                                         PFCPSessionEstablishmentResp)
from scapy.all import Ether, IP, Raw, UDP, wrpcap

from fivegcap.capture import read_pfcp_capture
from fivegcap.output import to_pfcp_dict
from fivegcap.pfcp import decode, pair_procedures

SMF = "10.0.0.1"
UPF = "10.0.0.2"


def _establishment_request(seq):
    m = PFCPSessionEstablishmentReq()
    m[0]["S"].set_val(0)
    m[0]["SeqNum"].set_val(seq)
    return m.to_bytes()


def _establishment_response(seq, cause):
    r = PFCPSessionEstablishmentResp()
    r[0]["S"].set_val(0)
    r[0]["SeqNum"].set_val(seq)
    for ie in r[1]._content:
        if ie[0].get_val() == 19:  # Cause
            ie[3].set_val(cause)
    return r.to_bytes()


def _segment(payload, src=SMF, dst=UPF, ts=0.0):
    pk = Ether() / IP(src=src, dst=dst) / \
        UDP(sport=8805, dport=8805) / Raw(load=payload)
    pk.time = ts
    return pk


def _decode(path):
    raw = read_pfcp_capture(str(path))
    return [decode(m.ts, m.data, m.src_ip, m.dst_ip, m.src_port, m.dst_port)
            for m in raw]


def test_request_response_accept(tmp_path):
    req = _establishment_request(1)
    rsp = _establishment_response(1, 1)  # Request accepted
    wrpcap(str(tmp_path / "x.pcap"),
           [_segment(req, ts=0.0), _segment(rsp, src=UPF, dst=SMF, ts=0.1)])
    msgs = _decode(tmp_path / "x.pcap")
    assert len(msgs) == 2
    assert all(m.unparsed is None for m in msgs)
    procedures, unpaired = pair_procedures(msgs)
    assert unpaired == []
    assert len(procedures) == 1
    p = procedures[0]
    assert p.kind == "session_establishment"
    assert p.outcome == "accept"
    assert p.cause == 1 and p.cause_name == "Request accepted"
    assert p.start_msg == "PFCP Session Establishment Request"
    assert p.end_msg == "PFCP Session Establishment Response"
    # Export contract: message "cause" stays the name (triage listing
    # contract), numeric code travels in "cause_code"; procedures carry both.
    d = to_pfcp_dict(msgs)
    assert d["unpaired_requests"] == 0
    rsp_msg = d["messages"][1]
    assert rsp_msg["cause"] == "Request accepted"
    assert rsp_msg["cause_code"] == 1
    assert d["procedures"][0]["cause"] == 1
    assert d["procedures"][0]["cause_name"] == "Request accepted"


def test_unanswered_request_is_timeout(tmp_path):
    wrpcap(str(tmp_path / "x.pcap"), [_segment(_establishment_request(1))])
    msgs = _decode(tmp_path / "x.pcap")
    assert len(msgs) == 1
    procedures, unpaired = pair_procedures(msgs)
    assert len(unpaired) == 1
    p = procedures[0]
    assert p.kind == "session_establishment"
    assert p.outcome == "timeout"
    assert p.end_msg is None and p.end_ts == p.start_ts
    assert p.cause is None and p.cause_name is None
    d = to_pfcp_dict(msgs)
    assert d["unpaired_requests"] == 1
    assert d["procedures"][0]["end_msg"] is None
    assert d["procedures"][0]["outcome"] == "timeout"


def test_retransmit_burst_kept(tmp_path):
    # Open5GS retransmits an unanswered request 3x (t1 = 2.5 s): 4 identical
    # frames, same seq. They stay distinct messages (the burst is physical
    # evidence of the timeout) but pair as one unpaired request / one
    # timeout procedure anchored at the first send.
    req = _establishment_request(7)
    wrpcap(str(tmp_path / "x.pcap"),
           [_segment(req, ts=t) for t in (0.0, 2.5, 5.0, 7.5)])
    msgs = _decode(tmp_path / "x.pcap")
    assert len(msgs) == 4
    assert [m.ts for m in msgs] == [0.0, 2.5, 5.0, 7.5]
    procedures, unpaired = pair_procedures(msgs)
    assert len(unpaired) == 1
    assert unpaired[0].ts == 0.0
    assert len(procedures) == 1
    assert procedures[0].outcome == "timeout"
    assert procedures[0].start_ts == 0.0


def test_reject_carries_numeric_cause(tmp_path):
    req = _establishment_request(2)
    rsp = _establishment_response(2, 75)  # No resources available
    wrpcap(str(tmp_path / "x.pcap"),
           [_segment(req, ts=0.0), _segment(rsp, src=UPF, dst=SMF, ts=0.1)])
    msgs = _decode(tmp_path / "x.pcap")
    procedures, unpaired = pair_procedures(msgs)
    assert unpaired == []
    p = procedures[0]
    assert p.outcome == "reject"
    assert p.cause == 75 and p.cause_name == "No resources available"
    d = to_pfcp_dict(msgs)
    assert d["procedures"][0]["cause"] == 75
    assert d["procedures"][0]["outcome"] == "reject"


def test_garbage_payload_degrades(tmp_path):
    wrpcap(str(tmp_path / "x.pcap"), [_segment(b"\x20\xff\x00\x00")])
    msgs = _decode(tmp_path / "x.pcap")
    assert len(msgs) == 1
    assert msgs[0].unparsed and "decode failed" in msgs[0].unparsed
    procedures, unpaired = pair_procedures(msgs)
    assert procedures == [] and unpaired == []
