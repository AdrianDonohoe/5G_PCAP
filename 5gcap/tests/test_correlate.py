"""Cross-plane correlation: strict key equality, ambiguity yields no link.

The merged export (analyze with --sbi) is the high seam: synthetic pcaps
built offline in tmp_path with the existing N2/SBI builders, asserted
against the export. `correlate` itself is a pure-function seam for the
cheap negative cases.
"""

import json

from pycrate_mobile.TS24501_FGMM import (
    FGMMRegistrationAccept,
    FGMMRegistrationRequest,
)
from scapy.all import wrpcap

from fivegcap.cli import analyze
from fivegcap.correlate import correlate
from fivegcap.flow import Flow
from fivegcap.nas import NasMsg
from fivegcap.ngap import NgapMsg
from fivegcap.pfcp import PfcpMsg
from fivegcap.sbi import SbiMsg
from synth import (_pkt, downlink_nas_transport, initial_ue_message,
                   pdu_session_setup_request, pdu_session_setup_response)
from test_nas import _reg_with_5gsid
from test_sbi import CLIENT, SERVER, _exchange, _headers, _segment
from test_pfcp import (IMSI_BCD, SMF, UPF, _est_req, _est_rsp_keyed,
                       _mod_req_keyed, _mod_rsp, _segment as _n4_segment)

# Null-scheme SUCI (IMSI 999700000000002), the same value the N2 and SBI
# sides of the merged-export test carry.
SUCI_NULL = [0, 0, 0, 1, [b"\x99\xf9\x07", b"\x00\x00", 0, 0, 0,
                          b"\x00\x00\x00\x00 "]]

CONN = frozenset({(CLIENT, 40000), (SERVER, 7777)})


def _flow(fid: int, supi: str | None) -> Flow:
    f = Flow(flow_id=fid, assoc=((45000, 38412)), ran_ue_id=fid,
             amf_ue_id=fid, partial=False)
    nas = NasMsg(name="5GMMRegistrationRequest", supi=supi)
    f.messages = [(NgapMsg(ts=0.0, assoc=(), stream=0, raw=b"",
                           name="InitialUEMessage", nas_pdu=b""), nas)]
    return f


def _req(i: int, stream: int, supi: str | None,
         unparsed: str | None = None) -> SbiMsg:
    return SbiMsg(ts=float(i), stream_id=stream, direction="request",
                  method="POST", path="/nudm-uecm/v1/registrations",
                  name=None if unparsed else "Nudm_UECM",
                  conn=CONN, src_ip=CLIENT, dst_ip=SERVER, src_port=40000,
                  dst_port=7777, supi=supi, unparsed=unparsed)


def _rsp(i: int, stream: int) -> SbiMsg:
    return SbiMsg(ts=float(i), stream_id=stream, direction="response",
                  status=200, name="Nudm_UECM", conn=CONN,
                  src_ip=SERVER, dst_ip=CLIENT, src_port=7777, dst_port=40000)


def _flow_tunnels(fid: int, tunnels: list) -> Flow:
    f = Flow(flow_id=fid, assoc=((45000, 38412)), ran_ue_id=fid,
             amf_ue_id=fid, partial=False)
    ng = NgapMsg(ts=0.0, assoc=(), stream=0, raw=b"",
                 name="PDUSessionResourceSetupRequest")
    ng.f_teids = tunnels
    f.messages = [(ng, None)]
    return f


def _n4(i: int, f_teids: list = (), unparsed: str | None = None) -> PfcpMsg:
    return PfcpMsg(ts=float(i), raw=b"", msg_type=50,
                   name="PFCP Session Establishment Request", seq=1,
                   f_teids=f_teids, unparsed=unparsed)


def test_exact_supi_join_links_request_and_its_response():
    flows = [_flow(1, "999700000000001"), _flow(2, None)]
    msgs = [_req(0, 1, "999700000000001"), _rsp(1, 1), _req(2, 3, None)]
    corr = correlate(flows, sbi_msgs=msgs)
    assert corr.sbi_flow == {0: 1, 1: 1, 2: None}
    assert corr.flow_sbi_refs == {1: [0, 1]}


def test_ambiguous_supi_yields_no_link():
    flows = [_flow(1, "999700000000001"), _flow(2, "999700000000001")]
    msgs = [_req(0, 1, "999700000000001")]
    corr = correlate(flows, sbi_msgs=msgs)
    assert corr.sbi_flow == {0: None}
    assert corr.flow_sbi_refs == {}


def test_refused_message_never_joins():
    flows = [_flow(1, "999700000000001")]
    msgs = [_req(0, 1, "999700000000001", unparsed="stream reset")]
    corr = correlate(flows, sbi_msgs=msgs)
    assert corr.sbi_flow == {0: None}


# --- N2<->N4 GTP tunnel join ------------------------------------------------


def test_exact_tunnel_join_links_establishment_and_modification():
    flows = [_flow_tunnels(1, [(56400, "10.53.0.13"), (1, "10.53.0.20")])]
    msgs = [_n4(0), _n4(1, [(56400, "10.53.0.13")]),
            _n4(2, [(1, "10.53.0.20")]), _n4(3)]
    corr = correlate(flows, n4_msgs=msgs)
    assert corr.n4_flow == {0: None, 1: 1, 2: 1, 3: None}
    assert corr.flow_n4_refs == {1: [1, 2]}


def test_ambiguous_tunnel_yields_no_link():
    flows = [_flow_tunnels(1, [(56400, "10.53.0.13")]),
             _flow_tunnels(2, [(56400, "10.53.0.13")])]
    msgs = [_n4(0, [(56400, "10.53.0.13")])]
    corr = correlate(flows, n4_msgs=msgs)
    assert corr.n4_flow == {0: None}
    assert corr.flow_n4_refs == {}


def test_refused_n4_message_never_joins():
    flows = [_flow_tunnels(1, [(56400, "10.53.0.13")])]
    msgs = [_n4(0, [(56400, "10.53.0.13")], unparsed="PFCP decode failed")]
    corr = correlate(flows, n4_msgs=msgs)
    assert corr.n4_flow == {0: None}


def test_message_spanning_two_flows_links_none():
    flows = [_flow_tunnels(1, [(56400, "10.53.0.13")]),
             _flow_tunnels(2, [(1, "10.53.0.20")])]
    msgs = [_n4(0, [(56400, "10.53.0.13"), (1, "10.53.0.20")])]
    corr = correlate(flows, n4_msgs=msgs)
    assert corr.n4_flow == {0: None}


def test_merged_export_carries_flow_links(tmp_path):
    # N2: one UE's registration (SUCI null-scheme, IMSI ...002) + its
    # accept; SBI: an auth request under the same identity (suci- path) +
    # its response. The join must land the SBI pair on flow 1.
    n2 = tmp_path / "n2.pcap"
    wrpcap(str(n2), [
        _pkt(0.000, initial_ue_message(_reg_with_5gsid(SUCI_NULL), 1),
             45000, 38412, 1001),
        _pkt(0.100, downlink_nas_transport(
            FGMMRegistrationAccept().to_bytes(), 1), 38412, 45000, 2001),
    ])
    sbi = tmp_path / "sbi.pcap"
    c2s, s2c = _exchange(
        _headers("/nudm-ueau/v1/suci-0-999-70-0000-0-0-0000000002/"
                 "security-information/generate-auth-data"), status=200)
    wrpcap(str(sbi), [_segment(CLIENT, 40000, SERVER, 7777, c2s),
                      _segment(SERVER, 7777, CLIENT, 40000, s2c)])
    merged = tmp_path / "merged.json"
    assert analyze(str(n2), str(merged), sbi_path=str(sbi)) == 0
    data = json.loads(merged.read_text())
    assert data["flows"][0]["sbi_refs"] == [0, 1]
    assert [m["flow_id"] for m in data["sbi"]["messages"]] == [1, 1]
    assert data["sbi"]["procedures"][0]["flow_id"] == 1

    # Single-plane invocation of the same N2 capture: no correlation keys.
    plain = tmp_path / "plain.json"
    assert analyze(str(n2), str(plain)) == 0
    single = json.loads(plain.read_text())
    assert "sbi" not in single
    assert "sbi_refs" not in single["flows"][0]
    assert single["kpis"] == data["kpis"]
    assert single["unassociated"] == data["unassociated"]
    assert single["flows"][0] == {k: v for k, v in data["flows"][0].items()
                                  if k != "sbi_refs"}


def test_merged_export_carries_n4_links(tmp_path):
    # N2: one UE's PDU-session setup — the request's UP transport layer
    # carries the UPF tunnel (56400 @ 10.53.0.13), the response's downlink
    # TNL carries the gNB tunnel (1 @ 10.53.0.20). N4: a session
    # establishment pair (Created PDR F-TEID = the UPF tunnel, User ID
    # evidence on the request) and a modification pair (Update FAR OHC = the
    # gNB tunnel, UE IP evidence). The establishment response and the
    # modification request join flow 1; the establishment request stays
    # unlinked (placeholder tunnels are never keys).
    n2 = tmp_path / "n2.pcap"
    wrpcap(str(n2), [
        _pkt(0.000, pdu_session_setup_request(56400, 0x0A35000D, 1),
             45000, 38412, 1001),
        _pkt(0.100, pdu_session_setup_response(1, 0x0A350014, 1),
             38412, 45000, 2001),
    ])
    n4 = tmp_path / "n4.pcap"
    wrpcap(str(n4), [
        _n4_segment(_est_req(1, bcd=IMSI_BCD), src=SMF, dst=UPF, ts=0.050),
        _n4_segment(_est_rsp_keyed(1, 56400, bytes([10, 53, 0, 13])),
                    src=UPF, dst=SMF, ts=0.080),
        _n4_segment(_mod_req_keyed(2, 1, bytes([10, 53, 0, 20]),
                                   ue_ip4=bytes([10, 45, 0, 2])),
                    src=SMF, dst=UPF, ts=0.090),
        _n4_segment(_mod_rsp(2), src=UPF, dst=SMF, ts=0.120),
    ])
    merged = tmp_path / "merged.json"
    assert analyze(str(n2), str(merged), n4_path=str(n4)) == 0
    data = json.loads(merged.read_text())
    assert data["flows"][0]["n4_refs"] == [1, 2]
    assert [m["flow_id"] for m in data["n4"]["messages"]] == [None, 1, 1, None]
    assert [m["user_id"] for m in data["n4"]["messages"]] == \
        ["999700000000002", None, None, None]
    assert [m["ue_ip"] for m in data["n4"]["messages"]] == \
        [None, None, "10.45.0.2", None]
    kinds = {p["kind"]: p for p in data["n4"]["procedures"]}
    assert kinds["session_establishment"]["flow_id"] == 1  # via its response
    assert kinds["session_modification"]["flow_id"] == 1   # via its request
    # No SBI given: no sbi_refs key and no SBI section.
    assert "sbi_refs" not in data["flows"][0]
    assert "sbi" not in data

    # Single-plane invocation of the same N2 capture: no correlation keys.
    plain = tmp_path / "plain.json"
    assert analyze(str(n2), str(plain)) == 0
    single = json.loads(plain.read_text())
    assert "n4" not in single
    assert "n4_refs" not in single["flows"][0]
    assert single["kpis"] == data["kpis"]
    assert single["unassociated"] == data["unassociated"]
    assert single["flows"][0] == {k: v for k, v in data["flows"][0].items()
                                  if k != "n4_refs"}