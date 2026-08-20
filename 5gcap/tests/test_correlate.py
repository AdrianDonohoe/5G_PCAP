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
from fivegcap.sbi import SbiMsg
from synth import _pkt, downlink_nas_transport, initial_ue_message
from test_nas import _reg_with_5gsid
from test_sbi import CLIENT, SERVER, _exchange, _headers, _segment

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