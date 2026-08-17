"""Flow and Procedure model per CONTEXT.md.

Flow  = all N2 signaling for one UE, associated by NGAP UE IDs.
Procedure = protocol-defined exchange with a start message and terminal outcome.
"""

from dataclasses import dataclass, field

from .ngap import NgapMsg
from .nas import decode as nas_decode

# NAS message names that open/close the v1 procedures (pycrate TS24501 names).
REG_START = "5GMMRegistrationRequest"
REG_END = {"5GMMRegistrationAccept", "5GMMRegistrationReject"}
PDU_START = "5GSMPDUSessionEstabRequest"
PDU_END = {"5GSMPDUSessionEstabAccept", "5GSMPDUSessionEstabReject"}

# NGAP-level fallback pairing: modern 5G protects NAS terminal outcomes, but the
# NGAP carriers of those outcomes stay visible. Used only when the flow has no
# completed NAS-level procedure of the same kind (see build_flows).
NGAP_ATTACH_START = "InitialUEMessage"
NGAP_ATTACH_END = {
    "InitialContextSetupRequest": "accept",
    "InitialContextSetupFailure": "reject",
}
NGAP_PDU_START = "PDUSessionResourceSetupRequest"
NGAP_PDU_END = {
    "PDUSessionResourceSetupResponse": "accept",
    "PDUSessionResourceSetupFailure": "reject",
}


@dataclass
class Procedure:
    kind: str                # "registration" | "pdu_session_est"
    start_ts: float
    start_msg: str
    end_ts: float | None = None
    end_msg: str | None = None
    outcome: str = "open"    # open | accept | reject


@dataclass
class Flow:
    flow_id: int
    assoc: tuple
    ran_ue_id: int | None
    amf_ue_id: int | None
    partial: bool
    messages: list = field(default_factory=list)   # (NgapMsg, NasMsg|None)
    procedures: list = field(default_factory=list)
    ciph_algo: int | None = None  # selected by the flow's SecurityModeCommand


def _nas_of(msg: NgapMsg, f: Flow):
    if not msg.nas_pdu:
        return None
    nas = nas_decode(msg.nas_pdu, ciph_algo=f.ciph_algo)
    if f.ciph_algo is None and nas.ciph_algo is not None:
        # The SMC carries the selected algorithms; later messages follow it.
        f.ciph_algo = nas.ciph_algo
    return nas


def build_flows(msgs: list[NgapMsg]) -> tuple[list[Flow], list[NgapMsg]]:
    """Group UE-associated messages into Flows; return non-UE traffic separately.

    The association key normalizes the SCTP pair direction: N2 signaling for one
    UE crosses both directions of the same association.
    """
    flows: dict[tuple, Flow] = {}
    order: list[Flow] = []
    unassociated: list[NgapMsg] = []
    next_id = 1

    def flow_for(msg: NgapMsg) -> Flow:
        nonlocal next_id
        assoc = frozenset(msg.assoc)
        key = (assoc, msg.ran_ue_id)
        if key in flows:
            return flows[key]
        f = Flow(
            flow_id=next_id,
            assoc=tuple(sorted(msg.assoc)),
            ran_ue_id=msg.ran_ue_id,
            amf_ue_id=msg.amf_ue_id,
            partial=msg.name != "InitialUEMessage",
        )
        next_id += 1
        flows[key] = f
        order.append(f)
        return f

    open_procs: dict[tuple, Procedure] = {}
    ngap_starts: dict[tuple, list[Procedure]] = {}

    def complete_ngap(f: Flow, kind: str, end_name: str, outcome: str, ts: float) -> None:
        # NGAP fallback only fires when no NAS-level procedure of this kind
        # completed in the flow (NAS plaintext is the more precise measurement).
        if any(p.kind == kind for p in f.procedures):
            ngap_starts.pop((f.flow_id, kind), None)
            return
        starts = ngap_starts.get((f.flow_id, kind), [])
        if not starts:
            return
        proc = starts.pop(0)
        proc.end_ts = ts
        proc.end_msg = end_name
        proc.outcome = outcome
        f.procedures.append(proc)

    for ng in msgs:
        if ng.ran_ue_id is None and ng.amf_ue_id is None:
            unassociated.append(ng)  # e.g. NGSetup, ErrorIndication
            continue
        f = flow_for(ng)
        if f.amf_ue_id is None and ng.amf_ue_id is not None:
            f.amf_ue_id = ng.amf_ue_id
        nas = _nas_of(ng, f)
        f.messages.append((ng, nas))
        if ng.name in (
            "UEContextReleaseRequest",
            "UEContextReleaseCommand",
            "UEContextReleaseComplete",
        ):
            # The signaling cycle ended without a context setup: any open
            # NGAP attach starts from earlier cycles are dead (prevents a
            # stale InitialUEMessage pairing with a later cycle's setup).
            ngap_starts.pop((f.flow_id, "registration"), None)
            ngap_starts.pop((f.flow_id, "pdu_session_est"), None)
        # NAS-level procedures close before the NGAP fallback check runs, so
        # a NAS terminal outcome carried by the NGAP end message (e.g. a
        # RegistrationAccept on the InitialContextSetupRequest) suppresses
        # the fallback instead of duplicating the procedure.
        if nas is not None and nas.name is not None and not nas.unparsed:
            name = nas.inner or nas.name
            if name == REG_START or name == PDU_START:
                open_procs[(f.flow_id, name)] = Procedure(
                    kind="registration" if name == REG_START else "pdu_session_est",
                    start_ts=ng.ts,
                    start_msg=name,
                )
            elif name in REG_END or name in PDU_END:
                pkey = (f.flow_id, REG_START if name in REG_END else PDU_START)
                proc = open_procs.pop(pkey, None)
                if proc is not None:
                    proc.end_ts = ng.ts
                    proc.end_msg = name
                    proc.outcome = "accept" if name.endswith("Accept") else "reject"
                    f.procedures.append(proc)
        if ng.name == NGAP_ATTACH_START:
            ngap_starts.setdefault((f.flow_id, "registration"), []).append(
                Procedure(kind="registration", start_ts=ng.ts, start_msg=ng.name)
            )
        elif ng.name in NGAP_ATTACH_END:
            complete_ngap(f, "registration", ng.name, NGAP_ATTACH_END[ng.name], ng.ts)
        elif ng.name == NGAP_PDU_START:
            ngap_starts.setdefault((f.flow_id, "pdu_session_est"), []).append(
                Procedure(kind="pdu_session_est", start_ts=ng.ts, start_msg=ng.name)
            )
        elif ng.name in NGAP_PDU_END:
            complete_ngap(f, "pdu_session_est", ng.name, NGAP_PDU_END[ng.name], ng.ts)
    return order, unassociated
