"""query_topology: infer network-element roles and UE/Flow relationships of a
decoded Capture purely from message content (CONTEXT.md "Topology" — no
external inventory or config is assumed).

Consumes 5gcap's two JSON exports (`5gcap analyze --json`): the N2 export
(write_json: flows / unassociated / kpis) and the N4 export (write_pfcp_json:
messages / procedures). Roles are inferred from message DIRECTIONS:

- gNB / AMF: the first InitialUEMessage (UE-initiated, so src = gNB,
  dst = AMF). 5gcap's JSON gives unassociated NGSetup messages no IPs, so the
  NGSetup exchange itself cannot be used.
- SMF / UPF: the PFCP Association Setup Request (CP -> UP) when the capture
  contains one — a capture starting after the core is up won't — else the
  first PFCP Session Establishment Request (also CP -> UP). Heartbeats flow
  in both directions and prove nothing.

Anything that cannot be determined is reported as unknown rather than
guessed, consistent with 5gcap's lenient-decode philosophy.
"""

from dataclasses import dataclass, field

UL = "InitialUEMessage"           # first UE-initiated N2 message
ASSOC_SETUP = "association setup request"          # PFCP msg type 2, CP -> UP
SESSION_ESTAB = "pfcp session establishment request"  # type 50, also CP -> UP


@dataclass
class NetworkElement:
    role: str        # "gNB" | "AMF" | "SMF" | "UPF"
    ip: str          # "unknown" when not inferable
    evidence: str    # the message whose direction proves the role


@dataclass
class UESummary:
    flow_id: int | None
    ran_ue_ngap_id: int | None
    amf_ue_ngap_id: int | None
    partial: bool
    message_count: int
    causes: list = field(default_factory=list)      # [(code, name)], deduped
    procedures: list = field(default_factory=list)  # dicts as 5gcap exported


@dataclass
class Topology:
    elements: list = field(default_factory=list)
    ues: list = field(default_factory=list)


def _t0(msgs):
    stamps = [m["ts"] for m in msgs
              if isinstance(m.get("ts"), (int, float))]
    return min(stamps, default=0.0)


def _infer_gnb_amf(flows):
    """(gNB ip, AMF ip, evidence) from the first InitialUEMessage."""
    all_msgs = [m for f in flows for m in f.get("messages", [])]
    t0 = _t0(all_msgs)
    for f in flows:
        for m in f.get("messages", []):
            if m.get("ngap") == UL and m.get("src_ip") and m.get("dst_ip"):
                return (m["src_ip"], m["dst_ip"],
                        f"{UL} src/dst @ +{m['ts'] - t0:.3f}s "
                        f"(N2, flow {f.get('flow_id', '?')})")
    return None, None, None


def _infer_smf_upf(n4):
    """(SMF ip, UPF ip, evidence); unknown when the capture can't prove it."""
    msgs = n4.get("messages", []) if isinstance(n4, dict) else []
    if not msgs:
        return None, None, "no N4 capture"
    t0 = _t0(msgs)
    for name in (ASSOC_SETUP, SESSION_ESTAB):
        for m in msgs:
            if name in (m.get("name") or "").lower() \
                    and m.get("src_ip") and m.get("dst_ip"):
                return (m["src_ip"], m["dst_ip"],
                        f"{m['name']} src/dst @ +{m['ts'] - t0:.3f}s (N4)")
    return None, None, "no PFCP CP->UP message (only heartbeats)"


def infer_topology(n2: dict, n4: dict | None = None) -> Topology:
    """Infer the Capture's Topology from 5gcap's N2 and N4 JSON exports."""
    flows = n2.get("flows", []) if isinstance(n2, dict) else []
    topo = Topology()

    gnb, amf, evidence = _infer_gnb_amf(flows)
    if gnb:
        topo.elements += [
            NetworkElement("gNB", gnb, evidence),
            NetworkElement("AMF", amf, evidence),
        ]
    else:
        unknown = "no IP-carrying N2 message"
        topo.elements += [
            NetworkElement("gNB", "unknown", unknown),
            NetworkElement("AMF", "unknown", unknown),
        ]

    smf, upf, evidence = _infer_smf_upf(n4)
    if smf:
        topo.elements += [
            NetworkElement("SMF", smf, evidence),
            NetworkElement("UPF", upf, evidence),
        ]
    else:
        topo.elements += [
            NetworkElement("SMF", "unknown", evidence or "no N4 capture"),
            NetworkElement("UPF", "unknown", evidence or "no N4 capture"),
        ]

    for f in flows:
        msgs = f.get("messages", [])
        causes = []
        for m in msgs:
            cause = m.get("nas_cause")
            if isinstance(cause, dict):
                pair = (cause.get("code"), cause.get("name"))
                if pair not in causes:
                    causes.append(pair)
        topo.ues.append(UESummary(
            flow_id=f.get("flow_id"),
            ran_ue_ngap_id=f.get("ran_ue_ngap_id"),
            amf_ue_ngap_id=f.get("amf_ue_ngap_id"),
            partial=bool(f.get("partial")),
            message_count=len(msgs),
            causes=causes,
            procedures=list(f.get("procedures", [])),
        ))
    return topo


def query_topology(n2: dict, n4: dict | None = None) -> str:
    """The Action's observation: a plain-text Topology report."""
    topo = infer_topology(n2, n4)
    lines = ["Topology (inferred from message content only):", "",
             "Network elements:"]
    for element in topo.elements:
        lines.append(f"  {element.role:<4} {element.ip:<15} "
                     f"({element.evidence})")
    lines += ["", f"UEs ({len(topo.ues)} N2 flow(s)):"]
    for ue in topo.ues:
        ran = ue.ran_ue_ngap_id if ue.ran_ue_ngap_id is not None else "?"
        amf = ue.amf_ue_ngap_id if ue.amf_ue_ngap_id is not None else "?"
        tag = " [PARTIAL]" if ue.partial else ""
        lines.append(f"  Flow {ue.flow_id}{tag}  RAN-UE-NGAP-ID={ran} "
                     f" AMF-UE-NGAP-ID={amf}")
        lines.append(f"    {ue.message_count} message(s)")
        for proc in ue.procedures:
            duration = (f"{proc['duration_ms']:.1f} ms"
                        if proc.get("duration_ms") is not None else "?")
            lines.append(f"    {proc.get('kind', '?')}: "
                         f"{proc.get('start_msg', '?')} -> "
                         f"{proc.get('end_msg') or '?'} "
                         f"[{proc.get('outcome', '?')}] {duration}")
        for code, name in ue.causes:
            lines.append(f"    cause #{code} {name}")
    return "\n".join(lines)
