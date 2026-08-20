"""NGAP decoding via pycrate (lenient: failures become unparsed notes)."""

import ast
import re
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
        # Commit only on full success: a mid-extraction failure leaves the
        # message refused-only, never half-decoded (decoded XOR refused).
        m.kind, m.proc_code, m.name = kind, proc_code, name
        m.ran_ue_id, m.amf_ue_id, m.nas_pdu = ran_ue_id, amf_ue_id, nas_pdu
        m.ies = ies
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
