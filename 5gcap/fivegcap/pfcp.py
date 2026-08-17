"""PFCP (N4) decoding via pycrate (lenient: failures become unparsed notes).

Request/response pairing uses the PFCP header's sequence number, matching
Open5GS/UERANSIM's own request-response correlation. This is a standalone N4
view: it does not attempt to correlate against N2/NGAP flows (nothing in a
PFCP message carries an NGAP UE ID), so it is reported separately from the
Flow/KPI vocabulary in CONTEXT.md, which is defined over the NGAP carrier.
"""

from dataclasses import dataclass, field

from pycrate_mobile.TS29244_PFCP import parse_PFCP, PFCPMsgType_dict, Cause_dict

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
    return m


@dataclass
class N4Procedure:
    kind: str
    start_ts: float
    end_ts: float
    start_msg: str
    end_msg: str
    outcome: str  # "accept" / "reject" / "unknown"


def pair_procedures(msgs: list[PfcpMsg]) -> tuple[list[N4Procedure], list[PfcpMsg]]:
    """Pairs request/response messages by sequence number. Returns
    (procedures, unpaired requests)."""
    pending: dict[int, PfcpMsg] = {}
    procedures: list[N4Procedure] = []
    for m in msgs:
        if m.unparsed or m.msg_type is None:
            continue
        if m.msg_type in REQ_KIND:
            pending[m.seq] = m
        elif (m.msg_type - 1) in REQ_KIND and m.seq in pending:
            req = pending.pop(m.seq)
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
                )
            )
    return procedures, list(pending.values())
