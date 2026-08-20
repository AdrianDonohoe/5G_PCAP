"""Terminal trace and JSON export."""

import json

from .correlate import Correlation
from .flow import Flow
from .kpi import KpiResult
from .ngap import NgapMsg
from .pfcp import PfcpMsg, N4Procedure, pair_procedures
from .sbi import SbiMsg, pair_procedures as pair_sbi_procedures


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
                if nas.cause_name:
                    nas_name += f" cause={nas.cause_name}"
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
        end = p.end_msg or "(no response)"
        print(f"  PROCEDURE {p.kind}: {p.start_msg} -> {end} [{p.outcome}] {ms:.1f} ms")


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
                    "src_ip": ng.src_ip,
                    "dst_ip": ng.dst_ip,
                    "ngap": ng.name,
                    "kind": ng.kind,
                    "nas": (nas.name if nas else None),
                    "nas_protected": (nas.protected if nas else None),
                    "nas_inner": (nas.inner if nas else None),
                    "nas_cause": (
                        {"code": nas.cause, "name": nas.cause_name}
                        if nas and nas.cause is not None else None
                    ),
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


def to_pfcp_dict(msgs: list[PfcpMsg],
                 flow_of: dict[int, int | None] | None = None) -> dict:
    """N4 plane export. The User ID and UE IP evidence fields are always
    present. With `flow_of` (message index -> flow id) every message gains
    a `flow_id` and each procedure follows its request's flow if linked,
    else its response's (the establishment key lives on the response)."""
    procedures, unpaired = pair_procedures(msgs)
    messages = [
        {
            "ts": m.ts,
            "src_ip": m.src_ip,
            "dst_ip": m.dst_ip,
            "src_port": m.src_port,
            "dst_port": m.dst_port,
            "name": m.name,
            "seq": m.seq,
            "seid": m.seid,
            "cause": m.cause_name,
            "cause_code": m.cause,
            "user_id": m.user_id,
            "ue_ip": m.ue_ip,
            "unparsed": m.unparsed,
        }
        for m in msgs
    ]
    proc_dicts = [
        {
            "kind": p.kind,
            "start_ts": p.start_ts,
            "end_ts": p.end_ts,
            "start_msg": p.start_msg,
            "end_msg": p.end_msg,
            "outcome": p.outcome,
            "cause": p.cause,
            "cause_name": p.cause_name,
            "duration_ms": (p.end_ts - p.start_ts) * 1000.0,
        }
        for p in procedures
    ]
    if flow_of is not None:
        for i, md in enumerate(messages):
            md["flow_id"] = flow_of[i]
        for pd, p in zip(proc_dicts, procedures):
            req_f = flow_of[p.req_index] if p.req_index is not None else None
            rsp_f = flow_of[p.rsp_index] if p.rsp_index is not None else None
            pd["flow_id"] = req_f if req_f is not None else rsp_f
    return {"messages": messages, "procedures": proc_dicts,
            "unpaired_requests": len(unpaired)}


def write_pfcp_json(msgs: list[PfcpMsg], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(to_pfcp_dict(msgs), fh, indent=2)


def print_sbi_trace(msgs: list[SbiMsg]) -> None:
    t0 = min((m.ts for m in msgs), default=0.0)
    procedures, unpaired = pair_sbi_procedures(msgs)
    print(f"{len(msgs)} SBI (HTTP/2) message(s), {len(procedures)} procedure(s) paired, "
          f"{unpaired} unpaired request(s)")
    print()
    for m in msgs:
        unparsed = f" [unparsed: {m.unparsed}]" if m.unparsed else ""
        if m.direction == "request":
            print(f"  {_fmt_ts(m.ts, t0)}  {m.method or '?'} {m.path or '?'}  "
                  f"({m.name or '?'}){unparsed}")
        else:
            print(f"  {_fmt_ts(m.ts, t0)}  "
                  f"{m.status if m.status is not None else '?'}  "
                  f"({m.name or '?'}){unparsed}")
    print()
    print("SBI procedures")
    for p in procedures:
        ms = (p.end_ts - p.start_ts) * 1000.0
        end = p.end_msg or "(no response)"
        print(f"  PROCEDURE {p.kind}: {p.start_msg} -> {end} [{p.outcome}] {ms:.1f} ms")


def to_sbi_dict(msgs: list[SbiMsg],
                flow_of: dict[int, int | None] | None = None) -> dict:
    """SBI plane export. With `flow_of` (message index -> flow id) every
    message and procedure record gains a `flow_id`; without it the export
    is exactly the single-plane one."""
    procedures, unpaired = pair_sbi_procedures(msgs)
    messages = [
        {
            "ts": m.ts,
            "src_ip": m.src_ip,
            "dst_ip": m.dst_ip,
            "src_port": m.src_port,
            "dst_port": m.dst_port,
            "stream_id": m.stream_id,
            "direction": m.direction,
            "method": m.method,
            "path": m.path,
            "status": m.status,
            "body_len": m.body_len,
            "service": m.name,
            "name": m.name,
            "problem_title": m.problem_title,
            "problem_cause": m.problem_cause,
            "unparsed": m.unparsed,
        }
        for m in msgs
    ]
    proc_dicts = [
        {
            "kind": p.kind,
            "start_ts": p.start_ts,
            "end_ts": p.end_ts,
            "start_msg": p.start_msg,
            "end_msg": p.end_msg,
            "outcome": p.outcome,
            "status": p.status,
        }
        for p in procedures
    ]
    if flow_of is not None:
        # A procedure inherits its request's flow via the exact (conn,
        # stream) pairing; procedures of refused or unjoined requests
        # carry flow_id null.
        req_idx = {(m.conn, m.stream_id): i for i, m in enumerate(msgs)
                   if m.direction == "request" and m.conn is not None}
        for i, md in enumerate(messages):
            md["flow_id"] = flow_of[i]
        for pd, p in zip(proc_dicts, procedures):
            key = (p.conn, p.stream_id)
            pd["flow_id"] = flow_of[req_idx[key]] if key in req_idx else None
    return {"messages": messages, "procedures": proc_dicts,
            "unpaired_requests": unpaired}


def write_sbi_json(msgs: list[SbiMsg], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(to_sbi_dict(msgs), fh, indent=2)


def to_merged_dict(flows: list[Flow], kpi: KpiResult,
                   unassociated: list[NgapMsg], corr: Correlation,
                   sbi_msgs: list[SbiMsg] | None = None,
                   n4_msgs: list[PfcpMsg] | None = None) -> dict:
    """Merged export: the single-plane dict, plus per flow the `sbi_refs`
    and/or `n4_refs` message indexes, and the "sbi"/"n4" sections (only for
    the planes given) whose message and procedure records carry the
    correlated `flow_id`."""
    out = to_dict(flows, kpi, unassociated)
    for fd in out["flows"]:
        if sbi_msgs is not None:
            fd["sbi_refs"] = corr.flow_sbi_refs.get(fd["flow_id"], [])
        if n4_msgs is not None:
            fd["n4_refs"] = corr.flow_n4_refs.get(fd["flow_id"], [])
    if sbi_msgs is not None:
        out["sbi"] = to_sbi_dict(sbi_msgs, flow_of=corr.sbi_flow)
    if n4_msgs is not None:
        out["n4"] = to_pfcp_dict(n4_msgs, flow_of=corr.n4_flow)
    return out


def write_merged_json(flows: list[Flow], kpi: KpiResult,
                      unassociated: list[NgapMsg], corr: Correlation,
                      path: str,
                      sbi_msgs: list[SbiMsg] | None = None,
                      n4_msgs: list[PfcpMsg] | None = None) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(to_merged_dict(flows, kpi, unassociated, corr,
                                 sbi_msgs, n4_msgs),
                  fh, indent=2)
