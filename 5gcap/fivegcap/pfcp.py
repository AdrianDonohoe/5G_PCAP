"""PFCP (N4) decoding via pycrate (lenient: failures become unparsed notes).

Request/response pairing uses the PFCP header's sequence number within one
direction (src/dst/seq): each node runs an independent sequence counter, and
the counters collide across directions on the live wire, so a seq-only key
would pair a request with the wrong peer's same-seq response. This is a
standalone N4 view: it does not attempt to correlate against N2/NGAP flows
(nothing in a PFCP message carries an NGAP UE ID), so it is reported
separately from the Flow/KPI vocabulary in CONTEXT.md, which is defined over
the NGAP carrier.
"""

from dataclasses import dataclass, field

from pycrate_mobile.TS29244_PFCP import parse_PFCP, PFCPMsgType_dict, Cause_dict

from .nas import _bcd_digits
from .ngap import _ip_str, _to_bytes

# Request message type -> response message type (request is always even,
# response is request + 1, per 3GPP TS 29.244).
REQ_KIND = {
    1: "heartbeat",
    3: "pfd_management",
    5: "association_setup",
    7: "association_update",
    9: "association_release",
    12: "node_report",
    14: "session_set_deletion",
    50: "session_establishment",
    52: "session_modification",
    54: "session_deletion",
    56: "session_report",
}


@dataclass
class PfcpMsg:
    ts: float
    raw: bytes
    msg_type: int | None = None
    name: str | None = None      # e.g. "PFCP Session Establishment Request"
    seq: int | None = None
    seid: int | None = None
    cause: int | None = None
    cause_name: str | None = None
    ies: dict = field(default_factory=dict)  # IE type -> value
    f_teids: list = field(default_factory=list)  # (teid, ip) join keys: the
        # establishment response's Created PDR F-TEID (the UPF endpoint) and
        # the modification request's Update FAR Outer Header Creation (the
        # gNB endpoint). Create-FAR placeholder teids are never keys.
    ue_ip: str | None = None     # UE IP address IE 93 (evidence, never a key)
    user_id: str | None = None   # User ID IE 141's IMSI (evidence, never a key)
    unparsed: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None


def decode(ts: float, data: bytes,
           src_ip: str | None = None, dst_ip: str | None = None,
           src_port: int | None = None, dst_port: int | None = None) -> PfcpMsg:
    m = PfcpMsg(ts=ts, raw=data, src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port)
    try:
        msg, err = parse_PFCP(data)
        if msg is None:
            m.unparsed = f"PFCP decode failed: error code {err}"
            return m
    except Exception as e:  # lenient: never fatal
        m.unparsed = f"PFCP decode failed: {e!r}"
        return m
    hdr = msg[0]
    m.msg_type = hdr["Type"].get_val()
    m.name = PFCPMsgType_dict.get(m.msg_type, f"type {m.msg_type}")
    m.seq = hdr["SeqNum"].get_val()
    m.seid = hdr["SEID"].get_val() if hdr["S"].get_val() else None
    if len(msg._content) > 1:
        for ie in msg[1]._content:
            ie_type = ie[0].get_val()
            ie_val = ie[3].get_val() if len(ie._content) > 3 else None
            m.ies[ie_type] = ie_val
            if ie_type == 19:  # Cause
                m.cause = ie_val
                m.cause_name = Cause_dict.get(ie_val, f"cause {ie_val}")
            elif ie_type == 8:  # Created PDR: the establishment join key
                key = _created_pdr_key(ie_val)
                if key is not None:
                    m.f_teids.append(key)
            elif ie_type == 10:  # Update FAR: the modification join key
                key = _update_far_key(ie_val)
                if key is not None:
                    m.f_teids.append(key)
            elif ie_type == 93:  # UE IP address (evidence)
                m.ue_ip = _ue_ip(ie_val)
            elif ie_type == 141:  # User ID (IMSI evidence)
                m.user_id = _user_id(ie_val)
    return m


def _created_pdr_key(val) -> tuple[int, str] | None:
    """The Created PDR's F-TEID as a (teid, ip) key, leniently. Only the
    session establishment response's Created PDR yields a key; the Create
    PDR's choose-id F-TEID and the Create FAR's placeholder teids are never
    keys. pycrate gives the PDR group's inner IE records ([type, len,
    flags, value]) flat."""
    try:
        if not isinstance(val, list):
            return None
        for item in val:
            recs = item if (isinstance(item, list) and item
                            and isinstance(item[0], list)) else [item]
            for rec in recs:
                if isinstance(rec, list) and rec and rec[0] == 21 \
                        and len(rec) > 3:
                    return _fteid_key(rec[3])
        return None
    except Exception:
        return None


def _update_far_key(val) -> tuple[int, str] | None:
    """The Update FAR's Outer Header Creation as a (teid, ip) key: it lives
    in the Update Forwarding Parameters (IE 11) of the Update FAR (IE 10)
    and carries the gNB endpoint. pycrate gives the FAR group's inner IE
    records flat; the Update Forwarding Parameters record's value is the
    list of its own inner IE records."""
    try:
        if not isinstance(val, list):
            return None
        for item in val:
            recs = item if (isinstance(item, list) and item
                            and isinstance(item[0], list)) else [item]
            for rec in recs:
                if not (isinstance(rec, list) and rec and rec[0] == 11
                        and len(rec) > 3):
                    continue
                fps = rec[3] if isinstance(rec[3], list) else []
                for fp in (fps if fps and isinstance(fps[0], list) else [fps]):
                    if isinstance(fp, list) and fp and fp[0] == 84 \
                            and len(fp) > 3:
                        key = _ohc_key(fp[3])
                        if key is not None:
                            return key
        return None
    except Exception:
        return None


def _fteid_key(val) -> tuple[int, str] | None:
    """(teid, ip) from a decoded F-TEID: [spare, CHID, CH, V6, V4, TEID,
    ipv4, ipv6] (absent IPs drop off the tail)."""
    try:
        if not isinstance(val, list) or len(val) < 6 \
                or not isinstance(val[5], int):
            return None
        for i in (6, 7):  # ipv4 then ipv6
            ip = _ip_str(_to_bytes(val[i])) if len(val) > i else None
            if ip:
                return val[5], ip
        return None
    except Exception:
        return None


def _ohc_key(val) -> tuple[int, str] | None:
    """(teid, ip) from a decoded Outer Header Creation: [8 desc flags,
    spare, N6, N19, TEID, ipv4, ipv6, port, ctag, stag, ext]. A description
    without a GTP-U header is no tunnel, so it is never a key."""
    try:
        if not isinstance(val, list) or len(val) < 13 \
                or not isinstance(val[11], int):
            return None
        if val[7] == 1:  # GTP-U/UDP/IPv4
            ip = _ip_str(_to_bytes(val[12]))
        elif val[6] == 1:  # GTP-U/UDP/IPv6
            ip = _ip_str(_to_bytes(val[13]))
        else:
            return None
        return (val[11], ip) if ip else None
    except Exception:
        return None


def _ue_ip(val) -> str | None:
    """The UE IP Address IE's IPv4/IPv6 (evidence). [spare, IP6PL, CHV6,
    CHV4, IPv6D, SD, V4, V6, ipv4, ipv6, prefdeleg, preflen, ext]."""
    try:
        if not isinstance(val, list) or len(val) < 9:
            return None
        for flag_i, addr_i in ((6, 8), (7, 9)):  # V4 then V6
            if val[flag_i] == 1:
                ip = _ip_str(_to_bytes(val[addr_i]))
                if ip:
                    return ip
        return None
    except Exception:
        return None


def _user_id(val) -> str | None:
    """The User ID IE's IMSI, BCD-decoded (evidence). [spare, NAIF,
    MSISDNF, IMEIF, IMSIF, IMSI, IMEI, MSISDN, NAI, ext]; the IMSI is a
    [len, bytes] pair when the IMSIF flag is set."""
    try:
        if not isinstance(val, list) or len(val) < 6:
            return None
        imsi = val[5]
        if not (isinstance(imsi, list) and len(imsi) == 2 and imsi[0] == 8):
            return None
        raw = _to_bytes(imsi[1])
        return _bcd_digits(raw) if raw else None
    except Exception:
        return None


@dataclass
class N4Procedure:
    kind: str
    start_ts: float
    end_ts: float
    start_msg: str
    end_msg: str | None
    outcome: str  # "accept" / "reject" / "unknown" / "timeout"
    cause: int | None = None
    cause_name: str | None = None
    req_index: int | None = None  # internal: message index of the request
    rsp_index: int | None = None  # internal: message index of the response


def pair_procedures(msgs: list[PfcpMsg]) -> tuple[list[N4Procedure], list[PfcpMsg]]:
    """Pairs request/response messages by (src, dst, seq). Returns
    (procedures, unpaired requests). A request never answered by capture
    end is a timeout procedure; retransmissions of a pending request are
    kept as distinct messages (the retry burst is physical evidence of the
    timeout) but pair against the first send."""
    pending: dict[tuple, tuple[PfcpMsg, int]] = {}
    procedures: list[N4Procedure] = []
    for i, m in enumerate(msgs):
        if m.unparsed or m.msg_type is None:
            continue
        if m.msg_type in REQ_KIND:
            key = (m.src_ip, m.src_port, m.dst_ip, m.dst_port, m.seq)
            if key not in pending:  # retransmit: keep the first send
                pending[key] = (m, i)
        elif (m.msg_type - 1) in REQ_KIND:
            # a response travels the request's path in reverse
            key = (m.dst_ip, m.dst_port, m.src_ip, m.src_port, m.seq)
            if key in pending:
                req, req_i = pending.pop(key)
                outcome = "unknown"
                if m.cause is not None:
                    outcome = "accept" if m.cause in (1, 2, 3) else "reject"
                procedures.append(
                    N4Procedure(
                        kind=REQ_KIND[m.msg_type - 1],
                        start_ts=req.ts,
                        end_ts=m.ts,
                        start_msg=req.name,
                        end_msg=m.name,
                        outcome=outcome,
                        cause=m.cause,
                        cause_name=m.cause_name,
                        req_index=req_i,
                        rsp_index=i,
                    )
                )
    for req, req_i in pending.values():
        procedures.append(
            N4Procedure(
                kind=REQ_KIND[req.msg_type],
                start_ts=req.ts,
                end_ts=req.ts,
                start_msg=req.name,
                end_msg=None,
                outcome="timeout",
                req_index=req_i,
            )
        )
    procedures.sort(key=lambda p: p.start_ts)
    return procedures, [req for req, _ in pending.values()]
