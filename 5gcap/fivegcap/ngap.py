"""NGAP decoding via pycrate (lenient: failures become unparsed notes)."""

import ast
import re
import socket
from dataclasses import dataclass, field

from pycrate_asn1dir.NGAP import NGAP_PDU_Descriptions as NGAP_D


@dataclass
class NgapMsg:
    ts: float
    assoc: tuple
    stream: int
    raw: bytes
    name: str | None = None          # e.g. "InitialUEMessage"
    kind: str | None = None          # initiatingMessage / successfulOutcome / unsuccessfulOutcome
    proc_code: int | None = None
    ran_ue_id: int | None = None
    amf_ue_id: int | None = None
    nas_pdu: bytes | None = None
    ies: dict = field(default_factory=dict)  # IE name -> value
    f_teids: list = field(default_factory=list)  # GTP tunnels (teid, ip) the
        # message declares: the SetupRequest's UPF endpoint, the
        # SetupResponse's gNB endpoint — the N2<->N4 join keys
    req_session_tunnels: dict = field(default_factory=dict)  # pDUSessionID ->
        # the SetupRequest item's UPF-endpoint tunnels — the per-session
        # refinement of the N2<->N4 join keys above
    rsp_session_counts: dict = field(default_factory=dict)  # pDUSessionID ->
        # SetupResponse item count in this message (the per-session N2 leg)
    unparsed: str | None = None      # decode failure note
    src_ip: str | None = None
    dst_ip: str | None = None


def decode(ts: float, assoc: tuple, stream: int, data: bytes,
           src_ip: str | None = None, dst_ip: str | None = None) -> NgapMsg:
    m = NgapMsg(ts=ts, assoc=assoc, stream=stream, raw=data,
                src_ip=src_ip, dst_ip=dst_ip)
    try:
        NGAP_D.NGAP_PDU.from_aper(data)
        val = NGAP_D.NGAP_PDU.get_val()
        # val: [kind, {procedureCode, criticality, value: [name, fields]}]
        # (a PDU with an unknown CHOICE extension can still parse, with
        # get_val() returning bytes instead of this structure — the .get
        # below then fails and is caught)
        kind, body = val[0], val[1]
        name = body.get("value", [None])[0]
        if name is not None and name.startswith("_unk_"):
            # pycrate's placeholder for a procedure code it doesn't know —
            # not a real decode, so refuse honestly
            m.unparsed = f"NGAP unknown procedure: {name}"
            return m
        proc_code = body.get("procedureCode")
        fields = body.get("value", [None, {}])[1] or {}
        ies = {}
        ran_ue_id = amf_ue_id = None
        nas_pdu = None
        for ie in fields.get("protocolIEs", []):
            ie_name = ie.get("value", [None])[0]
            ie_val = ie.get("value", [None])[1]
            ies[ie_name] = ie_val
            if ie_name == "RAN-UE-NGAP-ID":
                ran_ue_id = ie_val
            elif ie_name == "AMF-UE-NGAP-ID":
                amf_ue_id = ie_val
            elif ie_name == "NAS-PDU":
                nas_pdu = _to_bytes(ie_val)
        f_teids = _tunnels_of(ies)
        req_sessions, rsp_items = _pdu_sessions_of(ies)
        # Commit only on full success: a mid-extraction failure leaves the
        # message refused-only, never half-decoded (decoded XOR refused).
        m.kind, m.proc_code, m.name = kind, proc_code, name
        m.ran_ue_id, m.amf_ue_id, m.nas_pdu = ran_ue_id, amf_ue_id, nas_pdu
        m.ies = ies
        m.f_teids = f_teids
        m.req_session_tunnels = req_sessions
        m.rsp_session_counts = rsp_items
    except Exception as e:  # lenient: never fatal (parse or extraction)
        m.unparsed = f"NGAP decode failed: {e!r}"
    return m


def _to_bytes(val) -> bytes | None:
    """pycrate 0.8 dumps OCTET STRINGs as bytes-repr strings; parse them back.

    The dump mixes real control bytes with textual \\xNN escapes, which
    ast.literal_eval rejects — re-escape real non-printables first.
    """
    if isinstance(val, bytes):
        return val
    if isinstance(val, str):
        m = re.match(r"^b'(.*)'$", val, re.S)
        if m:
            inner = re.sub(
                r"[\x00-\x1f\x7f-\xff]",
                lambda c: "\\x%02x" % ord(c.group(0)),
                m.group(1),
            )
            try:
                parsed = ast.literal_eval("b'" + inner + "'")
                if isinstance(parsed, bytes):
                    return parsed
            except (ValueError, SyntaxError):
                pass
    return None


def _ip_str(raw: bytes) -> str | None:
    """Dotted-quad / colon form of an IPv4/IPv6 byte string."""
    try:
        if len(raw) == 4:
            return socket.inet_ntoa(raw)
        if len(raw) == 16:
            return socket.inet_ntop(socket.AF_INET6, raw)
    except OSError:
        pass
    return None


def _tunnel_of(gtp) -> tuple[int, str] | None:
    """(teid, ip) from a decoded gTPTunnel choice, leniently: either field
    unreadable means no tunnel (the strict join must not half-match)."""
    try:
        if not (isinstance(gtp, (list, tuple)) and len(gtp) > 1
                and gtp[0] == "gTPTunnel"):
            return None
        fields = gtp[1]
        teid = _to_bytes(fields.get("gTP-TEID"))
        if not teid:
            return None
        addr = fields.get("transportLayerAddress")
        if isinstance(addr, (list, tuple)) and len(addr) > 1 \
                and isinstance(addr[0], int):
            # a BIT STRING comes back as [integer, bit count]
            raw = addr[0].to_bytes((addr[1] + 7) // 8, "big")
        else:
            raw = _to_bytes(addr)
        ip = _ip_str(raw) if raw else None
        if teid and ip:
            return int.from_bytes(teid, "big"), ip
        return None
    except Exception:
        return None


def _tunnels_of(ies: dict) -> list:
    """The GTP tunnels an N2 message declares, leniently: the PDU-session
    SetupRequest's UP transport layer information (the UPF endpoint) and the
    SetupResponse's downlink TNL information (the gNB endpoint)."""
    tunnels = []
    for ie_name, ie_val in ies.items():
        if ie_name == "PDUSessionResourceSetupListSUReq":
            for item in ie_val if isinstance(ie_val, list) else []:
                if not isinstance(item, dict):
                    continue
                xfer = item.get("pDUSessionResourceSetupRequestTransfer")
                if not (isinstance(xfer, (list, tuple)) and len(xfer) > 1
                        and isinstance(xfer[1], dict)):
                    continue
                for pie in xfer[1].get("protocolIEs", []):
                    if pie.get("id") != 139:  # UPTransportLayerInformation
                        continue
                    t = _tunnel_of(pie.get("value", [None])[1])
                    if t is not None:
                        tunnels.append(t)
        elif ie_name == "PDUSessionResourceSetupListSURes":
            for item in ie_val if isinstance(ie_val, list) else []:
                if not isinstance(item, dict):
                    continue
                xfer = item.get("pDUSessionResourceSetupResponseTransfer")
                if not (isinstance(xfer, (list, tuple)) and len(xfer) > 1
                        and isinstance(xfer[1], dict)):
                    continue
                dl = xfer[1].get("dLQosFlowPerTNLInformation")
                for per_tnl in (dl if isinstance(dl, list) else [dl]):
                    if isinstance(per_tnl, dict):
                        t = _tunnel_of(per_tnl.get(
                            "uPTransportLayerInformation"))
                        if t is not None:
                            tunnels.append(t)
    return tunnels


def _pdu_sessions_of(ies: dict) -> tuple[dict, dict]:
    """Per-session anchors from the setup lists: the SetupRequest items'
    UPF-endpoint tunnels keyed by pDUSessionID, and the SetupResponse
    items' counts keyed by pDUSessionID. Lenient like `_tunnels_of`: an
    unreadable item or id yields nothing."""
    req_sessions: dict[int, set] = {}
    rsp_items: dict[int, int] = {}
    for ie_name, ie_val in ies.items():
        if ie_name == "PDUSessionResourceSetupListSUReq":
            for item in ie_val if isinstance(ie_val, list) else []:
                if not isinstance(item, dict):
                    continue
                sid = item.get("pDUSessionID")
                if isinstance(sid, bool) or not isinstance(sid, int):
                    continue
                xfer = item.get("pDUSessionResourceSetupRequestTransfer")
                if not (isinstance(xfer, (list, tuple)) and len(xfer) > 1
                        and isinstance(xfer[1], dict)):
                    continue
                tunnels = req_sessions.setdefault(sid, set())
                for pie in xfer[1].get("protocolIEs", []):
                    if pie.get("id") != 139:  # UPTransportLayerInformation
                        continue
                    t = _tunnel_of(pie.get("value", [None])[1])
                    if t is not None:
                        tunnels.add(t)
        elif ie_name == "PDUSessionResourceSetupListSURes":
            for item in ie_val if isinstance(ie_val, list) else []:
                if not isinstance(item, dict):
                    continue
                sid = item.get("pDUSessionID")
                if isinstance(sid, bool) or not isinstance(sid, int):
                    continue
                rsp_items[sid] = rsp_items.get(sid, 0) + 1
    return req_sessions, rsp_items
