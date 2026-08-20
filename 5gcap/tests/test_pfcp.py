"""PFCP (N4) decoder tests over synthetic UDP pcaps.

Offline by construction: the pcaps are built in tmp_path from pycrate-encoded
PFCP frames (the decoder under test is a passive reader of their wire bytes)
and wrpcap'd as Ethernet/IP/UDP packets on port 8805.
"""

import struct

from pycrate_mobile.TS29244_PFCP import (PFCPSessionEstablishmentReq,
                                         PFCPSessionEstablishmentResp)
from scapy.all import Ether, IP, Raw, UDP, wrpcap

from fivegcap.capture import read_pfcp_capture
from fivegcap.output import to_pfcp_dict
from fivegcap.pfcp import decode, pair_procedures

SMF = "10.0.0.1"
UPF = "10.0.0.2"

# Hand-built tunnel/evidence IEs: the join keys and evidence of ticket #9,
# byte-exact per TS 29.244 (S=0 header: version+spare, type, length, 3-byte
# seq, priority/spare byte, then IE TLVs).
IMSI_BCD = b"\x99\x79\x00\x00\x00\x00\x00\xf2"  # 999700000000002
UPF_TUNNEL = (56400, "10.53.0.13")
GNB_TUNNEL = (1, "10.53.0.20")


def _ie(t: int, v: bytes) -> bytes:
    return struct.pack("!HH", t, len(v)) + v


def _pfcp(msg_type: int, seq: int, *ies: bytes) -> bytes:
    body = b"".join(ies)
    return (bytes([0x20, msg_type]) + struct.pack("!H", len(body) + 4)
            + seq.to_bytes(3, "big") + b"\x00" + body)


def _fteid_ie(teid: int, ip4: bytes) -> bytes:
    # F-TEID: flags 0x11 (V4 + TEID), teid, ipv4
    return _ie(21, b"\x11" + struct.pack("!I", teid) + ip4)


def _ohc_ie(teid: int, ip4: bytes) -> bytes:
    # Outer Header Creation: desc GTP-U/UDP/IPv4, teid, ipv4, port 0
    return _ie(84, b"\x01\x00" + struct.pack("!I", teid) + ip4 + b"\x00\x00")


def _est_req(seq: int, bcd: bytes | None = None, extra: bytes = b"") -> bytes:
    body = (_ie(141, b"\x01" + bytes([len(bcd)]) + bcd) if bcd else b"") + extra
    return _pfcp(50, seq, body)


def _est_rsp_keyed(seq: int, teid: int, ip4: bytes) -> bytes:
    created_pdr = _ie(8, _ie(56, b"\x00\x04") + _fteid_ie(teid, ip4))
    return _pfcp(51, seq, created_pdr, _ie(19, b"\x01"))


def _mod_req_keyed(seq: int, teid: int, ip4: bytes,
                   ue_ip4: bytes | None = None) -> bytes:
    update_far = _ie(10, _ie(108, b"\x00\x00\x00\x00") + _ie(11, _ohc_ie(teid, ip4)))
    ue_ip = _ie(93, b"\x02" + ue_ip4) if ue_ip4 else b""
    return _pfcp(52, seq, update_far, ue_ip)


def _mod_rsp(seq: int, cause: int = 1) -> bytes:
    return _pfcp(53, seq, _ie(19, bytes([cause])))


def _create_far(teid: int, ip4: bytes) -> bytes:
    # The establishment request's Create FAR: its Outer Header Creation
    # carries a placeholder teid — never a join key.
    return _ie(3, _ie(108, b"\x00\x00\x00\x00") + _ie(4, _ohc_ie(teid, ip4)))


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
    # Open5GS retransmits an unanswered request at 2.5 s intervals
    # (live-verified: 3 sends per attempt -- the ~7.5 s give-up pre-empts
    # the 3rd retransmit); four frames here stress the decoder's shape.
    # They stay distinct messages (the burst is physical evidence of the
    # timeout) but pair as one unpaired request / one timeout procedure
    # anchored at the first send.
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


# --- #9: tunnel keys and evidence extraction --------------------------------


def test_created_pdr_fteid_is_the_establishment_key():
    m = decode(0.0, _est_rsp_keyed(1, UPF_TUNNEL[0], bytes([10, 53, 0, 13])),
               SMF, UPF, 8805, 8805)
    assert m.unparsed is None
    assert m.f_teids == [UPF_TUNNEL]


def test_update_far_ohc_is_the_modification_key():
    m = decode(0.0, _mod_req_keyed(2, GNB_TUNNEL[0], bytes([10, 53, 0, 20])),
               SMF, UPF, 8805, 8805)
    assert m.unparsed is None
    assert m.f_teids == [GNB_TUNNEL]


def test_create_far_placeholder_teid_is_never_a_key():
    m = decode(0.0, _est_req(3, bcd=IMSI_BCD,
                             extra=_create_far(13, bytes([10, 53, 0, 12]))),
               SMF, UPF, 8805, 8805)
    assert m.unparsed is None
    assert m.f_teids == []


def test_user_id_imsi_carried_as_evidence():
    m = decode(0.0, _est_req(1, bcd=IMSI_BCD), SMF, UPF, 8805, 8805)
    assert m.unparsed is None
    assert m.user_id == "999700000000002"
    assert m.f_teids == []
    d = to_pfcp_dict([m])
    assert d["messages"][0]["user_id"] == "999700000000002"


def test_ue_ip_carried_as_evidence():
    m = decode(0.0, _mod_req_keyed(2, GNB_TUNNEL[0], bytes([10, 53, 0, 20]),
                                   ue_ip4=bytes([10, 45, 0, 2])),
               SMF, UPF, 8805, 8805)
    assert m.unparsed is None
    assert m.ue_ip == "10.45.0.2"
    d = to_pfcp_dict([m])
    assert d["messages"][0]["ue_ip"] == "10.45.0.2"


def test_truncated_created_pdr_degrades_leniently():
    # A Created PDR whose F-TEID ends mid-field: decode-or-refuse — never a
    # raise, never a half-built key.
    body = _ie(8, _ie(56, b"\x00\x04") + _ie(21, b"\x11\x00\x00\xdc"))
    m = decode(0.0, _pfcp(51, 1, body), SMF, UPF, 8805, 8805)
    assert m.f_teids == []
    assert m.user_id is None and m.ue_ip is None
