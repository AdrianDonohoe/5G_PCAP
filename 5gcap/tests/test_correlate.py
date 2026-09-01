"""Cross-plane correlation: strict key equality, ambiguity yields no link.

The merged export (analyze with --sbi) is the high seam: synthetic pcaps
built offline in tmp_path with the existing N2/SBI builders, asserted
against the export. `correlate` itself is a pure-function seam for the
cheap negative cases.
"""

import json

import pytest
from pycrate_mobile.TS24501_FGMM import (
    FGMMRegistrationAccept,
    FGMMRegistrationRequest,
)
from scapy.all import wrpcap

from fivegcap.cli import analyze
from fivegcap.correlate import Correlation, correlate
from fivegcap.flow import Flow
from fivegcap.kpi import cross_plane_kpis
from fivegcap.nas import NasMsg
from fivegcap.ngap import NgapMsg, decode as ngap_decode
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

# --- #10: cross-plane PDU-session KPIs ---------------------------------------


def _kpi_flow(fid: int, setup_ts: float) -> Flow:
    f = Flow(flow_id=fid, assoc=((45000, 38412)), ran_ue_id=fid,
             amf_ue_id=fid, partial=False)
    ng = NgapMsg(ts=setup_ts, assoc=(), stream=0, raw=b"",
                 name="PDUSessionResourceSetupResponse")
    f.messages = [(ng, None)]
    return f


def _kpi_session_flow(fid: int,
                      sessions: list[tuple[int, float | None,
                                          tuple[int, str] | None]],
                      ) -> Flow:
    """Flow whose setup messages carry per-session anchors: each
    (sid, rsp_ts, upf_tunnel) yields a SetupRequest item declaring the
    session's UPF-endpoint tunnel and, when rsp_ts is given, a
    SetupResponse item at rsp_ts."""
    msgs = []
    for sid, rsp_ts, tunnel in sessions:
        req = NgapMsg(ts=0.0, assoc=(), stream=0, raw=b"",
                      name="PDUSessionResourceSetupRequest")
        if tunnel is not None:
            req.req_session_tunnels = {sid: {tunnel}}
        msgs.append((req, None))
        if rsp_ts is not None:
            rsp = NgapMsg(ts=rsp_ts, assoc=(), stream=0, raw=b"",
                          name="PDUSessionResourceSetupResponse")
            rsp.rsp_session_counts = {sid: 1}
            msgs.append((rsp, None))
    f = Flow(flow_id=fid, assoc=((45000, 38412)), ran_ue_id=fid,
             amf_ue_id=fid, partial=False)
    f.messages = msgs
    return f


def _kpi_sbi(ts: float, dst_ip: str, pdu_session_id: int | None = None) -> SbiMsg:
    m = SbiMsg(ts=ts, stream_id=1, direction="request", method="POST",
               path="/nsmf-pdusession/v1/sm-contexts",
               name="Nsmf_PDUSession", conn=CONN, src_ip=CLIENT,
               dst_ip=dst_ip, src_port=40000, dst_port=7777)
    m.pdu_session_id = pdu_session_id
    return m


def _kpi_est_rsp(ts: float, smf_ip: str,
                 f_teids: list[tuple[int, str]] | None = None) -> PfcpMsg:
    m = PfcpMsg(ts=ts, raw=b"", msg_type=51,
                name="PFCP Session Establishment Response", seq=1,
                src_ip=UPF, dst_ip=smf_ip)
    if f_teids is not None:
        m.f_teids = list(f_teids)
    return m


def _kpi_corr(flow_n4_refs=None, flow_sbi_refs=None) -> Correlation:
    c = Correlation()
    c.flow_n4_refs = flow_n4_refs or {}
    c.flow_sbi_refs = flow_sbi_refs or {}
    return c


def test_cross_plane_kpis_exact_values():
    # One complete flow: create 0.040 at the session's SMF, N4
    # establishment response 0.080, N2 SetupResponse 0.100.
    flows = [_kpi_flow(1, 0.100)]
    sbi = [_kpi_sbi(0.040, SMF)]
    n4 = [_kpi_est_rsp(0.080, SMF)]
    corr = _kpi_corr({1: [0]}, {1: [0]})
    k = cross_plane_kpis(flows, corr, sbi, n4)
    assert k["sbi_to_n4_ms"] == pytest.approx(40.0)
    assert k["n4_to_n2_ms"] == pytest.approx(20.0)
    assert k["sbi_to_n2_ms"] == pytest.approx(60.0)


def test_create_at_another_smf_is_not_the_leg():
    # Two creates join the flow: one at another SMF instance, one at the
    # SMF that ran the session (the N4 establishment response's dst).
    flows = [_kpi_flow(1, 0.100)]
    sbi = [_kpi_sbi(0.030, "10.0.0.9"), _kpi_sbi(0.040, SMF)]
    n4 = [_kpi_est_rsp(0.080, SMF)]
    corr = _kpi_corr({1: [0]}, {1: [0, 1]})
    k = cross_plane_kpis(flows, corr, sbi, n4)
    assert k["sbi_to_n4_ms"] == pytest.approx(40.0)
    assert k["sbi_to_n2_ms"] == pytest.approx(60.0)


def test_duplicate_creates_at_the_session_smf_exclude_the_flow():
    # Two creates at the same SMF: which one anchored the session is
    # unknowable, so the SBI-leg KPIs exclude the flow; n4_to_n2 stands.
    flows = [_kpi_flow(1, 0.100)]
    sbi = [_kpi_sbi(0.040, SMF), _kpi_sbi(0.041, SMF)]
    n4 = [_kpi_est_rsp(0.080, SMF)]
    corr = _kpi_corr({1: [0]}, {1: [0, 1]})
    k = cross_plane_kpis(flows, corr, sbi, n4)
    assert k["sbi_to_n4_ms"] is None
    assert k["n4_to_n2_ms"] == pytest.approx(20.0)
    assert k["sbi_to_n2_ms"] is None


def test_missing_leg_excludes_only_the_kpis_that_need_it():
    # No N4 establishment response: n4_to_n2 and sbi_to_n4 are excluded,
    # but the single unambiguous create still anchors sbi_to_n2.
    flows = [_kpi_flow(1, 0.100)]
    sbi = [_kpi_sbi(0.040, SMF)]
    corr = _kpi_corr({}, {1: [0]})
    k = cross_plane_kpis(flows, corr, sbi, [])
    assert k["sbi_to_n4_ms"] is None
    assert k["n4_to_n2_ms"] is None
    assert k["sbi_to_n2_ms"] == pytest.approx(60.0)


def test_two_session_flow_contributes_two_legs_per_kpi():
    # Sessions 1 and 2, both complete: creates 0.040/0.200 at the SMF,
    # establishment responses 0.080/0.260 keyed by their session's UPF
    # tunnel, SetupResponses 0.100/0.300. Legs 40/60 (sbi->n4), 20/40
    # (n4->n2), 60/100 (sbi->n2) -> means 50/30/80.
    flows = [_kpi_session_flow(1, [
        (1, 0.100, (56400, "10.53.0.13")),
        (2, 0.300, (56401, "10.53.0.14"))])]
    sbi = [_kpi_sbi(0.040, SMF, pdu_session_id=1),
           _kpi_sbi(0.200, SMF, pdu_session_id=2)]
    n4 = [_kpi_est_rsp(0.080, SMF, [(56400, "10.53.0.13")]),
          _kpi_est_rsp(0.260, SMF, [(56401, "10.53.0.14")])]
    corr = _kpi_corr({1: [0, 1]}, {1: [0, 1]})
    k = cross_plane_kpis(flows, corr, sbi, n4)
    assert k["sbi_to_n4_ms"] == pytest.approx(50.0)
    assert k["n4_to_n2_ms"] == pytest.approx(30.0)
    assert k["sbi_to_n2_ms"] == pytest.approx(80.0)


def test_session_missing_a_leg_is_excluded_from_its_kpis():
    # Session 2 has no create: sbi->n4 and sbi->n2 see only session 1
    # (40/60), n4->n2 still sees both sessions (20 + 40 -> 30).
    flows = [_kpi_session_flow(1, [
        (1, 0.100, (56400, "10.53.0.13")),
        (2, 0.300, (56401, "10.53.0.14"))])]
    sbi = [_kpi_sbi(0.040, SMF, pdu_session_id=1)]
    n4 = [_kpi_est_rsp(0.080, SMF, [(56400, "10.53.0.13")]),
          _kpi_est_rsp(0.260, SMF, [(56401, "10.53.0.14")])]
    corr = _kpi_corr({1: [0, 1]}, {1: [0]})
    k = cross_plane_kpis(flows, corr, sbi, n4)
    assert k["sbi_to_n4_ms"] == pytest.approx(40.0)
    assert k["n4_to_n2_ms"] == pytest.approx(30.0)
    assert k["sbi_to_n2_ms"] == pytest.approx(60.0)


def test_ambiguous_create_excludes_only_the_sbi_kpis():
    # Two creates for session 1: the SBI leg is ambiguous, so sbi->n4 and
    # sbi->n2 drop the session; n4->n2 stands on the exact N4/N2 legs.
    flows = [_kpi_session_flow(1, [(1, 0.100, (56400, "10.53.0.13"))])]
    sbi = [_kpi_sbi(0.040, SMF, pdu_session_id=1),
           _kpi_sbi(0.041, SMF, pdu_session_id=1)]
    n4 = [_kpi_est_rsp(0.080, SMF, [(56400, "10.53.0.13")])]
    corr = _kpi_corr({1: [0]}, {1: [0, 1]})
    k = cross_plane_kpis(flows, corr, sbi, n4)
    assert k["sbi_to_n4_ms"] is None
    assert k["n4_to_n2_ms"] == pytest.approx(20.0)
    assert k["sbi_to_n2_ms"] is None


def test_session_missing_est_is_excluded_from_the_kpis_that_need_it():
    # Session 2 has no N4 establishment response: sbi->n4 and n4->n2 see
    # only session 1 (40/20); sbi->n2 sees both (60 + 100 -> 80).
    flows = [_kpi_session_flow(1, [
        (1, 0.100, (56400, "10.53.0.13")),
        (2, 0.300, (56401, "10.53.0.14"))])]
    sbi = [_kpi_sbi(0.040, SMF, pdu_session_id=1),
           _kpi_sbi(0.200, SMF, pdu_session_id=2)]
    n4 = [_kpi_est_rsp(0.080, SMF, [(56400, "10.53.0.13")])]
    corr = _kpi_corr({1: [0]}, {1: [0, 1]})
    k = cross_plane_kpis(flows, corr, sbi, n4)
    assert k["sbi_to_n4_ms"] == pytest.approx(40.0)
    assert k["n4_to_n2_ms"] == pytest.approx(20.0)
    assert k["sbi_to_n2_ms"] == pytest.approx(80.0)


def test_session_missing_setup_is_excluded_from_the_kpis_that_need_it():
    # Session 2 has no N2 SetupResponse: n4->n2 and sbi->n2 see only
    # session 1 (20/60); sbi->n4 still sees both (40 + 60 -> 50).
    flows = [_kpi_session_flow(1, [
        (1, 0.100, (56400, "10.53.0.13")),
        (2, None, (56401, "10.53.0.14"))])]
    sbi = [_kpi_sbi(0.040, SMF, pdu_session_id=1),
           _kpi_sbi(0.200, SMF, pdu_session_id=2)]
    n4 = [_kpi_est_rsp(0.080, SMF, [(56400, "10.53.0.13")]),
          _kpi_est_rsp(0.260, SMF, [(56401, "10.53.0.14")])]
    corr = _kpi_corr({1: [0, 1]}, {1: [0, 1]})
    k = cross_plane_kpis(flows, corr, sbi, n4)
    assert k["sbi_to_n4_ms"] == pytest.approx(50.0)
    assert k["n4_to_n2_ms"] == pytest.approx(20.0)
    assert k["sbi_to_n2_ms"] == pytest.approx(60.0)


def test_est_response_matching_two_sessions_excludes_only_the_n4_kpis():
    # One establishment response whose Created-PDR tunnel appears in two
    # sessions' SetupRequest items: the anchor is ambiguous, so sbi->n4
    # and n4->n2 exclude both sessions — never a guess. The SBI legs are
    # per-session exact on their own, so sbi->n2 stands (60 + 100 -> 80).
    flows = [_kpi_session_flow(1, [
        (1, 0.100, (56400, "10.53.0.13")),
        (2, 0.300, (56400, "10.53.0.13"))])]
    sbi = [_kpi_sbi(0.040, SMF, pdu_session_id=1),
           _kpi_sbi(0.200, SMF, pdu_session_id=2)]
    n4 = [_kpi_est_rsp(0.080, SMF, [(56400, "10.53.0.13")])]
    corr = _kpi_corr({1: [0]}, {1: [0, 1]})
    k = cross_plane_kpis(flows, corr, sbi, n4)
    assert k["sbi_to_n4_ms"] is None
    assert k["n4_to_n2_ms"] is None
    assert k["sbi_to_n2_ms"] == pytest.approx(80.0)


def test_merged_export_carries_cross_plane_kpis(tmp_path):
    # The n4-links synthetic pair plus the SBI leg: the sm-contexts create
    # (body-only supi ...002) at the N4 SMF and its 201. Create 0.040, N4
    # establishment response 0.080, N2 SetupResponse 0.100 -> 40/20/60 ms.
    # The registration pair gives the flow its SUPI so the create joins.
    n2 = tmp_path / "n2.pcap"
    wrpcap(str(n2), [
        _pkt(0.000, initial_ue_message(_reg_with_5gsid(SUCI_NULL), 1),
             45000, 38412, 1001),
        _pkt(0.050, downlink_nas_transport(
            FGMMRegistrationAccept().to_bytes(), 1), 38412, 45000, 2001),
        _pkt(0.060, pdu_session_setup_request(56400, 0x0A35000D, 1),
             45000, 38412, 1002),
        _pkt(0.100, pdu_session_setup_response(1, 0x0A350014, 1),
             38412, 45000, 2002),
    ])
    n4 = tmp_path / "n4.pcap"
    wrpcap(str(n4), [
        _n4_segment(_est_req(1, bcd=IMSI_BCD), src=SMF, dst=UPF, ts=0.050),
        _n4_segment(_est_rsp_keyed(1, 56400, bytes([10, 53, 0, 13])),
                    src=UPF, dst=SMF, ts=0.080),
        _n4_segment(_mod_req_keyed(2, 1, bytes([10, 53, 0, 20])),
                    src=SMF, dst=UPF, ts=0.090),
        _n4_segment(_mod_rsp(2), src=UPF, dst=SMF, ts=0.120),
    ])
    sbi = tmp_path / "sbi.pcap"
    c2s, s2c = _exchange(
        _headers("/nsmf-pdusession/v1/sm-contexts"),
        request_body=b'{"supi": "imsi-999700000000002", "pduSessionId": 1}',
        status=201)
    pk1 = _segment(SERVER, 40000, SMF, 7777, c2s)
    pk1.time = 0.040
    pk2 = _segment(SMF, 7777, SERVER, 40000, s2c)
    pk2.time = 0.060
    wrpcap(str(sbi), [pk1, pk2])
    merged = tmp_path / "merged.json"
    assert analyze(str(n2), str(merged),
                   sbi_path=str(sbi), n4_path=str(n4)) == 0
    kpis = json.loads(merged.read_text())["kpis"]
    assert kpis["sbi_to_n4_ms"] == pytest.approx(40.0)
    assert kpis["n4_to_n2_ms"] == pytest.approx(20.0)
    assert kpis["sbi_to_n2_ms"] == pytest.approx(60.0)


def test_setup_items_decode_per_session_anchors():
    # The wire-level extraction: the builders' setup-list items carry
    # pDUSessionID 1, so each decoded message anchors session 1 with its
    # swapped tunnel.
    req = ngap_decode(0.0, (), 0, pdu_session_setup_request(56400, 0x0A35000D, 1))
    assert req.req_session_tunnels == {1: {(56400, "10.53.0.13")}}
    assert req.rsp_session_counts == {}
    rsp = ngap_decode(0.0, (), 0, pdu_session_setup_response(1, 0x0A350014, 1))
    assert rsp.rsp_session_counts == {1: 1}
    assert rsp.req_session_tunnels == {}
