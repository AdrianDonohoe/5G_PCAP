"""Terminal trace and JSON export."""

import json

from .flow import Flow
from .kpi import KpiResult
from .ngap import NgapMsg
from .pfcp import PfcpMsg, N4Procedure, pair_procedures


def _fmt_ts(ts: float, t0: float) -> str:
    return f"{ts - t0:9.3f}s"


def print_trace(flows: list[Flow], kpi: KpiResult, unassociated: list[NgapMsg]) -> None:
    t0 = min([m.ts for f in flows for m, _ in f.messages] + [m.ts for m in unassociated], default=0.0)
    total_msgs = sum(len(f.messages) for f in flows)
    print(f"{len(flows)} flow(s), {total_msgs} UE-associated NGAP message(s), "
          f"{len(unassociated)} non-UE message(s)")
    print()
    for f in flows:
        ran = f.ran_ue_id if f.ran_ue_id is not None else "?"
        amf = f.amf_ue_id if f.amf_ue_id is not None else "?"
        tag = " [PARTIAL]" if f.partial else ""
        print(f"Flow {f.flow_id}{tag}  RAN-UE-NGAP-ID={ran} AMF-UE-NGAP-ID={amf}")
        for ng, nas in f.messages:
            nas_name = ""
            if nas is not None:
                nas_name = f"  NAS: {nas.name or '?'}"
                if nas.protected:
                    nas_name += " (protected" + (f", inner={nas.inner})" if nas.inner else ")")
                if nas.unparsed:
                    nas_name += f" [unparsed: {nas.unparsed}]"
            unparsed = f" [unparsed: {ng.unparsed}]" if ng.unparsed else ""
            print(f"  {_fmt_ts(ng.ts, t0)}  {ng.name or '?'}{unparsed}{nas_name}")
        for p in f.procedures:
            ms = (p.end_ts - p.start_ts) * 1000.0
            print(
                f"  PROCEDURE {p.kind}: {p.start_msg} -> {p.end_msg} "
                f"[{p.outcome}] {ms:.1f} ms"
            )
        print()
    if unassociated:
        print("Non-UE-associated messages")
        for ng in unassociated:
            unparsed = f" [unparsed: {ng.unparsed}]" if ng.unparsed else ""
            print(f"  {_fmt_ts(ng.ts, t0)}  {ng.name or '?'}{unparsed}")
        print()
    print("KPIs")
    if kpi.attach_time_ms is not None:
        print(f"  attach time (mean): {kpi.attach_time_ms:.1f} ms "
              f"(n={len(kpi.attach_times_ms)})")
    else:
        print("  attach time: n/a (no complete procedures)")
    if kpi.pdu_session_time_ms is not None:
        print(f"  PDU session establishment time (mean): {kpi.pdu_session_time_ms:.1f} ms "
              f"(n={len(kpi.pdu_session_times_ms)})")
    else:
        print("  PDU session establishment time: n/a")
    if kpi.success_rate is not None:
        print(f"  procedure success rate: {kpi.success_rate:.1%} "
              f"({kpi.successes}/{kpi.successes + kpi.failures})")
    else:
        print("  procedure success rate: n/a (no terminal outcomes observed)")


def print_pfcp_trace(msgs: list[PfcpMsg]) -> None:
    t0 = min((m.ts for m in msgs), default=0.0)
    procedures, unpaired = pair_procedures(msgs)
    print(f"{len(msgs)} PFCP (N4) message(s), {len(procedures)} procedure(s) paired, "
          f"{len(unpaired)} unpaired request(s)")
    print()
    for m in msgs:
        unparsed = f" [unparsed: {m.unparsed}]" if m.unparsed else ""
        seid = f" SEID={m.seid}" if m.seid is not None else ""
        cause = f" cause={m.cause_name}" if m.cause_name else ""
        print(f"  {_fmt_ts(m.ts, t0)}  {m.name or '?'} seq={m.seq}{seid}{cause}{unparsed}")
    print()
    print("N4 procedures")
    for p in procedures:
        ms = (p.end_ts - p.start_ts) * 1000.0
        print(f"  PROCEDURE {p.kind}: {p.start_msg} -> {p.end_msg} [{p.outcome}] {ms:.1f} ms")


def to_dict(flows: list[Flow], kpi: KpiResult, unassociated: list[NgapMsg]) -> dict:
    def flow_dict(f: Flow) -> dict:
        return {
            "flow_id": f.flow_id,
            "ran_ue_ngap_id": f.ran_ue_id,
            "amf_ue_ngap_id": f.amf_ue_id,
            "partial": f.partial,
            "messages": [
                {
                    "ts": ng.ts,
                    "ngap": ng.name,
                    "kind": ng.kind,
                    "nas": (nas.name if nas else None),
                    "nas_protected": (nas.protected if nas else None),
                    "nas_inner": (nas.inner if nas else None),
                    "unparsed": ng.unparsed or (nas.unparsed if nas else None),
                }
                for ng, nas in f.messages
            ],
            "procedures": [
                {
                    "kind": p.kind,
                    "start_ts": p.start_ts,
                    "end_ts": p.end_ts,
                    "start_msg": p.start_msg,
                    "end_msg": p.end_msg,
                    "outcome": p.outcome,
                    "duration_ms": (p.end_ts - p.start_ts) * 1000.0 if p.end_ts else None,
                }
                for p in f.procedures
            ],
        }

    return {
        "kpis": {
            "attach_time_ms": kpi.attach_time_ms,
            "pdu_session_time_ms": kpi.pdu_session_time_ms,
            "procedure_success_rate": kpi.success_rate,
            "procedure_successes": kpi.successes,
            "procedure_failures": kpi.failures,
        },
        "flows": [flow_dict(f) for f in flows],
        "unassociated": [
            {"ts": ng.ts, "ngap": ng.name, "unparsed": ng.unparsed}
            for ng in unassociated
        ],
    }


def write_json(flows: list[Flow], kpi: KpiResult, unassociated: list[NgapMsg], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(to_dict(flows, kpi, unassociated), fh, indent=2)


def to_pfcp_dict(msgs: list[PfcpMsg]) -> dict:
    procedures, unpaired = pair_procedures(msgs)
    return {
        "messages": [
            {
                "ts": m.ts,
                "name": m.name,
                "seq": m.seq,
                "seid": m.seid,
                "cause": m.cause_name,
                "unparsed": m.unparsed,
            }
            for m in msgs
        ],
        "procedures": [
            {
                "kind": p.kind,
                "start_ts": p.start_ts,
                "end_ts": p.end_ts,
                "start_msg": p.start_msg,
                "end_msg": p.end_msg,
                "outcome": p.outcome,
                "duration_ms": (p.end_ts - p.start_ts) * 1000.0,
            }
            for p in procedures
        ],
        "unpaired_requests": len(unpaired),
    }


def write_pfcp_json(msgs: list[PfcpMsg], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(to_pfcp_dict(msgs), fh, indent=2)
