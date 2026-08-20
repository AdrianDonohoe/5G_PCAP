"""Synthetic capture builder for KPI tests.

Uses real captured NGAP messages from the modem-test fixture as round-trip
templates, swapping the NAS-PDU bytes for pycrate-encoded NAS messages. Produces
a deterministic pcap with known timestamps and known KPI values.
"""

from pathlib import Path

from scapy.all import Ether, IP, SCTP, SCTPChunkData, wrpcap
from pycrate_asn1dir.NGAP import NGAP_PDU_Descriptions as NGAP_D
from pycrate_mobile.TS24501_FGMM import (
    FGMMRegistrationAccept,
    FGMMRegistrationReject,
    FGMMRegistrationRequest,
)
from pycrate_mobile.TS24501_FGSM import (
    FGSMPDUSessionEstabAccept,
    FGSMPDUSessionEstabRequest,
)

FIXTURE = Path(__file__).parent / "fixtures" / "modem_testrun.pcap"


def _ngap_template(name: str) -> list:
    """Decode the first real message of `name` and return its value dict."""
    from scapy.all import rdpcap, SCTPChunkData

    for pk in rdpcap(str(FIXTURE)):
        if not pk.haslayer(SCTPChunkData):
            continue
        ch = pk[SCTPChunkData]
        if ch.proto_id != 60 or not ch.data or not (ch.beginning and ch.ending):
            continue
        NGAP_D.NGAP_PDU.from_aper(bytes(ch.data))
        val = NGAP_D.NGAP_PDU.get_val()
        if val[1].get("value", [None])[0] == name:
            return val
    raise RuntimeError(f"no {name} template found in fixture")


def _ngap_bytes(template: list, nas_pdu: bytes, ran_ue_id: int) -> bytes:
    val = _copy(template)
    ies = val[1]["value"][1]["protocolIEs"]
    for ie in ies:
        ie_name = ie["value"][0]
        # get_val returns IE values as tuples; set_val only accepts the same shape
        if ie_name == "NAS-PDU":
            ie["value"] = (ie_name, nas_pdu)  # set_val accepts real bytes here
        elif ie_name == "RAN-UE-NGAP-ID":
            ie["value"] = (ie_name, ran_ue_id)
    NGAP_D.NGAP_PDU.set_val(val)
    return NGAP_D.NGAP_PDU.to_aper()


def _copy(x):
    if isinstance(x, dict):
        return {k: _copy(v) for k, v in x.items()}
    if isinstance(x, tuple):
        return tuple(_copy(v) for v in x)
    if isinstance(x, list):
        return [_copy(v) for v in x]
    return x


def initial_ue_message(nas_pdu: bytes, ran_ue_id: int) -> bytes:
    """Wire bytes of an InitialUEMessage carrying `nas_pdu`.

    Public so the fuzz smoke's mutation baseline shares the exact
    composition build_synthetic uses — the two cannot diverge.
    """
    return _ngap_bytes(_ngap_template("InitialUEMessage"), nas_pdu, ran_ue_id)


def downlink_nas_transport(nas_pdu: bytes, ran_ue_id: int) -> bytes:
    """Wire bytes of a DownlinkNASTransport carrying `nas_pdu` (the
    initial_ue_message counterpart)."""
    return _ngap_bytes(_ngap_template("DownlinkNASTransport"), nas_pdu, ran_ue_id)


def _pkt(ts: float, ngap: bytes, sport: int, dport: int, tsn: int) -> bytes:
    sctp = SCTP(sport=sport, dport=dport)
    sctp /= SCTPChunkData(
        proto_id=60, tsn=tsn, stream_id=0, stream_seq=0,
        beginning=1, ending=1, data=ngap,
    )
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / sctp
    pkt.time = ts
    return pkt


def build_synthetic(path: str) -> None:
    down_nas = _ngap_template("DownlinkNASTransport")
    up_nas = _ngap_template("UplinkNASTransport")

    nas_reg_req = FGMMRegistrationRequest().to_bytes()
    nas_reg_acc = FGMMRegistrationAccept().to_bytes()
    nas_reg_rej = FGMMRegistrationReject().to_bytes()
    nas_pdu_req = FGSMPDUSessionEstabRequest().to_bytes()
    nas_pdu_acc = FGSMPDUSessionEstabAccept().to_bytes()

    pkts = [
        # registration #1: complete accept, 100 ms
        _pkt(0.000, initial_ue_message(nas_reg_req, 1), 45000, 38412, 1001),
        _pkt(0.100, _ngap_bytes(down_nas, nas_reg_acc, 1), 38412, 45000, 2001),
        # pdu session establishment: complete accept, 50 ms
        _pkt(0.200, _ngap_bytes(up_nas, nas_pdu_req, 1), 45000, 38412, 1002),
        _pkt(0.250, _ngap_bytes(down_nas, nas_pdu_acc, 1), 38412, 45000, 2002),
        # registration #2: reject, 30 ms
        _pkt(5.000, initial_ue_message(nas_reg_req, 1), 45000, 38412, 1003),
        _pkt(5.030, _ngap_bytes(down_nas, nas_reg_rej, 1), 38412, 45000, 2003),
        # a retransmitted chunk (same association + TSN as 1003) — must be dropped
        _pkt(5.010, initial_ue_message(nas_reg_req, 1), 45000, 38412, 1003),
    ]
    wrpcap(path, pkts)
