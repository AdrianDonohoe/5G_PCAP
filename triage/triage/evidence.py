"""inspect_decoded_evidence: the Action that reads 5gcap's decode output.

CONTEXT.md: Evidence is "a concrete fact drawn from 5gcap's decode output —
a specific message, IE, or Cause value". This tool turns an Evidence handle
into its decoded content. Bare handles list what exists so the LATS expand
step can enumerate the Action space deterministically:

    kpis              capture KPIs
    flows             one line per N2 flow
    flow:<id>         one flow: procedure summary + numbered message list
    flow:<id>:<i>     one N2 message (1-based index, as listed)
    unassociated      NGAP messages not tied to a UE flow (NGSetup)
    unassociated:<i>  one such message
    n4                one line per PFCP message
    n4:<i>            one PFCP message
    sbi               one line per SBI (HTTP/2) message
    sbi:<i>           one SBI message

Lenient by design (ADR-0001): unrecognized or out-of-range handles degrade
to an honest "no such evidence" observation, never a crash; capture dicts
are read with .get() so a missing key merely omits a field. The inputs are
5gcap's --json exports (N2 = {kpis, flows, unassociated}, N4 and SBI =
{messages, procedures, unpaired_requests}); their shape is 5gcap's
contract, not this module's. The merged export embeds the N4/SBI sections
in the N2 file and tags each flow with the message indexes it correlates
to (n4_refs/sbi_refs): flow:<id> lists those correlated messages.
"""

import json
from dataclasses import dataclass
from pathlib import Path

HANDLES = ("kpis, flows, unassociated, n4, sbi, flow:<id>, flow:<id>:<i>, "
           "unassociated:<i>, n4:<i>, or sbi:<i>")


@dataclass
class DecodedCapture:
    """5gcap's decoded output: the N2 export plus optional N4/SBI exports."""
    n2: dict
    n4: dict | None = None
    sbi: dict | None = None


def load_capture(n2_path: Path, n4_path: Path | None = None,
                 sbi_path: Path | None = None) -> DecodedCapture:
    """Load the --json exports; file/JSON errors propagate to the CLI.

    A merged export embeds the plane sections in the N2 file: without an
    explicit plane path those embedded sections are loaded instead. An
    explicit path always wins."""
    n2 = json.loads(Path(n2_path).read_text(encoding="utf-8"))
    n4 = json.loads(Path(n4_path).read_text(encoding="utf-8")) \
        if n4_path is not None else \
        (n2["n4"] if isinstance(n2.get("n4"), dict) else None)
    sbi = json.loads(Path(sbi_path).read_text(encoding="utf-8")) \
        if sbi_path is not None else \
        (n2["sbi"] if isinstance(n2.get("sbi"), dict) else None)
    return DecodedCapture(n2=n2, n4=n4, sbi=sbi)


def _unrecognized(handle: str) -> str:
    return (f'inspect_decoded_evidence: unrecognized handle "{handle}"; '
            f"expected {HANDLES}")


def fmt_ts(ts) -> str:
    return f"{ts:.3f}" if isinstance(ts, (int, float)) else str(ts)


def _msg_line(msg: dict) -> str:
    """One compact line for a flow message listing."""
    parts = [f"{msg.get('src_ip') or '?'}->{msg.get('dst_ip') or '?'}",
             msg.get("ngap") or "?"]
    nas = msg.get("nas_inner") or msg.get("nas")
    if nas:
        parts.append(nas + (" (protected)" if msg.get("nas_protected")
                            else ""))
    cause = msg.get("nas_cause")
    if cause:
        parts.append(f"cause={cause.get('name')} (#{cause.get('code')})")
    if msg.get("unparsed"):
        parts.append(f"[unparsed: {msg.get('unparsed')}]")
    return "  ".join(parts)


def _procedure_line(p: dict) -> str:
    return (f"{p.get('kind')}: {p.get('outcome')}, "
            f"{p.get('duration_ms', 0):.1f} ms "
            f"({p.get('start_msg')} -> {p.get('end_msg')})")


def _kpis_view(capture: DecodedCapture) -> str:
    kpis = capture.n2.get("kpis") or {}
    lines = ["Decode KPIs:"]
    for key, value in kpis.items():
        lines.append(f"  {key}={value:.3f}" if isinstance(value, float)
                     else f"  {key}={value}")
    return "\n".join(lines)


def _flows_listing(capture: DecodedCapture) -> str:
    flows = capture.n2.get("flows") or []
    lines = [f"Capture flows ({len(flows)}):"]
    for flow in flows:
        state = "partial" if flow.get("partial") else "complete"
        procs = ", ".join(_procedure_line(p)
                          for p in flow.get("procedures") or [])
        lines.append(f"  flow {flow.get('flow_id')}: {state}, "
                     f"{len(flow.get('messages') or [])} message(s)"
                     + (f", {procs}" if procs else ""))
    return "\n".join(lines)


def _flow_detail(capture: DecodedCapture, flow: dict) -> str:
    msgs = flow.get("messages") or []
    lines = [f"Flow {flow.get('flow_id')} "
             f"(RAN-UE-NGAP-ID {flow.get('ran_ue_ngap_id')}, "
             f"AMF-UE-NGAP-ID {flow.get('amf_ue_ngap_id')}, "
             f"{'partial' if flow.get('partial') else 'complete'}):"]
    lines += [f"  [{i}] {fmt_ts(m.get('ts'))}  {_msg_line(m)}"
              for i, m in enumerate(msgs, 1)]
    procs = flow.get("procedures") or []
    if procs:
        lines.append("  procedures:")
        lines += [f"    {_procedure_line(p)}" for p in procs]
    # The merged export's per-flow refs: the plane messages this flow
    # correlates to, listed with their n4:<i>/sbi:<i> handles so the
    # search can follow up. Out-of-range refs degrade to omission.
    if capture.n4 is not None:
        n4_msgs = capture.n4.get("messages") or []
        refs = flow.get("n4_refs") or []
        if refs:
            lines.append(f"  correlated N4 message(s) ({len(refs)}):")
            for ref in refs:
                if ref >= len(n4_msgs):
                    continue
                msg = n4_msgs[ref]
                lines.append(f"    [n4:{ref + 1}] {fmt_ts(msg.get('ts'))}  "
                             f"{msg.get('src_ip') or '?'}->"
                             f"{msg.get('dst_ip') or '?'}  "
                             f"{msg.get('name') or '?'}")
    if capture.sbi is not None:
        sbi_msgs = capture.sbi.get("messages") or []
        refs = flow.get("sbi_refs") or []
        if refs:
            lines.append(f"  correlated SBI message(s) ({len(refs)}):")
            for ref in refs:
                if ref >= len(sbi_msgs):
                    continue
                msg = sbi_msgs[ref]
                if msg.get("direction") == "request":
                    what = f"{msg.get('method') or '?'} {msg.get('path') or '?'}"
                else:
                    status = msg.get("status")
                    what = f"-> {status if status is not None else '?'}"
                lines.append(f"    [sbi:{ref + 1}] {fmt_ts(msg.get('ts'))}  "
                             f"{what}")
    return "\n".join(lines)


def _n2_message_view(flow_id: int, i: int, msg: dict) -> str:
    lines = [f"Evidence flow:{flow_id}:{i}:",
             f"  ts={fmt_ts(msg.get('ts'))}",
             f"  {msg.get('src_ip') or '?'} -> {msg.get('dst_ip') or '?'}"]
    ngap = f"ngap={msg.get('ngap') or '?'}"
    if msg.get("kind"):
        ngap += f" ({msg.get('kind')})"
    lines.append(f"  {ngap}")
    if msg.get("nas"):
        lines.append(f"  nas={msg.get('nas')}"
                     + (" (protected)" if msg.get("nas_protected") else ""))
    if msg.get("nas_inner"):
        lines.append(f"  nas_inner={msg.get('nas_inner')}")
    cause = msg.get("nas_cause")
    if cause:
        lines.append(f"  nas_cause: {cause.get('name')} (#{cause.get('code')})")
    if msg.get("unparsed"):
        lines.append(f"  unparsed: {msg.get('unparsed')}")
    return "\n".join(lines)


def _unassociated_listing(capture: DecodedCapture) -> str:
    msgs = capture.n2.get("unassociated") or []
    lines = [f"Unassociated NGAP messages ({len(msgs)}):"]
    lines += [f"  [{i}] {fmt_ts(m.get('ts'))}  {m.get('ngap') or '?'}"
              for i, m in enumerate(msgs, 1)]
    return "\n".join(lines)


def _unassociated_view(i: int, msg: dict) -> str:
    lines = [f"Evidence unassociated:{i}:",
             f"  ts={fmt_ts(msg.get('ts'))}",
             f"  ngap={msg.get('ngap') or '?'}"]
    if msg.get("unparsed"):
        lines.append(f"  unparsed: {msg.get('unparsed')}")
    return "\n".join(lines)


def _n4_listing(capture: DecodedCapture) -> str:
    msgs = capture.n4.get("messages") or []
    lines = [f"N4 (PFCP) messages ({len(msgs)}):"]
    seen = set()
    for i, msg in enumerate(msgs, 1):
        key = (msg.get("src_ip"), msg.get("dst_ip"), msg.get("seq"))
        retransmit = key in seen
        seen.add(key)
        line = (f"  [{i}] {fmt_ts(msg.get('ts'))}  "
                f"{msg.get('src_ip') or '?'}->{msg.get('dst_ip') or '?'}  "
                f"{msg.get('name') or '?'}")
        if retransmit:
            line += "  (retransmit)"
        if msg.get("seid") is not None:
            line += f"  seid={msg.get('seid')}"
        if msg.get("cause"):
            line += f'  cause="{msg.get("cause")}"'
        if msg.get("unparsed"):
            line += f"  [unparsed: {msg.get('unparsed')}]"
        lines.append(line)
    return "\n".join(lines)


def _n4_view(i: int, msg: dict, msgs: list) -> str:
    lines = [f"Evidence n4:{i}:",
             f"  ts={fmt_ts(msg.get('ts'))}",
             f"  {msg.get('src_ip') or '?'}:{msg.get('src_port')} -> "
             f"{msg.get('dst_ip') or '?'}:{msg.get('dst_port')}",
             f"  name={msg.get('name') or '?'}"]
    key = (msg.get("src_ip"), msg.get("dst_ip"), msg.get("seq"))
    if any(m.get("src_ip") == key[0] and m.get("dst_ip") == key[1]
           and m.get("seq") == key[2] for m in msgs[:i - 1]):
        lines.append("  retransmit: true")
    if msg.get("seq") is not None:
        lines.append(f"  seq={msg.get('seq')}")
    if msg.get("seid") is not None:
        lines.append(f"  seid={msg.get('seid')}")
    if msg.get("cause"):
        lines.append(f'  cause="{msg.get("cause")}"')
    if msg.get("unparsed"):
        lines.append(f"  unparsed: {msg.get('unparsed')}")
    return "\n".join(lines)


def _sbi_listing(capture: DecodedCapture) -> str:
    msgs = capture.sbi.get("messages") or []
    lines = [f"SBI (HTTP/2) messages ({len(msgs)}):"]
    for i, msg in enumerate(msgs, 1):
        line = f"  [{i}] {fmt_ts(msg.get('ts'))}  "
        if msg.get("direction") == "request":
            line += f"{msg.get('method') or '?'} {msg.get('path') or '?'}"
        else:
            line += f"-> {msg.get('status') if msg.get('status') is not None else '?'}"
        line += f"  ({msg.get('name') or '?'})"
        if msg.get("problem_title"):
            line += f'  problem="{msg.get("problem_title")}"'
        if msg.get("problem_cause"):
            line += f'  cause="{msg.get("problem_cause")}"'
        if msg.get("unparsed"):
            line += f"  [unparsed: {msg.get('unparsed')}]"
        lines.append(line)
    return "\n".join(lines)


def _sbi_view(i: int, msg: dict) -> str:
    lines = [f"Evidence sbi:{i}:",
             f"  ts={fmt_ts(msg.get('ts'))}",
             f"  {msg.get('src_ip') or '?'}:{msg.get('src_port')} -> "
             f"{msg.get('dst_ip') or '?'}:{msg.get('dst_port')}",
             f"  direction={msg.get('direction') or '?'}"]
    if msg.get("direction") == "request":
        lines.append(f"  method={msg.get('method') or '?'}")
        lines.append(f"  path={msg.get('path') or '?'}")
    else:
        status = msg.get("status")
        lines.append(f"  status={status if status is not None else '?'}")
    lines.append(f"  name={msg.get('name') or '?'}")
    if msg.get("stream_id") is not None:
        lines.append(f"  stream_id={msg.get('stream_id')}")
    if msg.get("problem_title"):
        lines.append(f'  problem_title="{msg.get("problem_title")}"')
    if msg.get("problem_cause"):
        lines.append(f'  problem_cause="{msg.get("problem_cause")}"')
    if msg.get("unparsed"):
        lines.append(f"  unparsed: {msg.get('unparsed')}")
    return "\n".join(lines)


def _dispatch_indexed(msgs: list, kind: str, handle: str,
                      view) -> str:
    """Shared n4:<i> / unassociated:<i> parsing + bounds checks."""
    try:
        idx = int(handle.split(":")[1])
    except (ValueError, IndexError):
        return _unrecognized(handle)
    if not 1 <= idx <= len(msgs):
        return (f"inspect_decoded_evidence: {kind} has {len(msgs)} "
                f"message(s); no message {idx}")
    return view(idx, msgs[idx - 1])


def _dispatch_flow(capture: DecodedCapture, handle: str) -> str:
    parts = handle.split(":")
    flows = capture.n2.get("flows") or []
    if len(parts) == 2 or len(parts) == 3:
        try:
            flow_id = int(parts[1])
            msg_idx = int(parts[2]) if len(parts) == 3 else None
        except ValueError:
            return _unrecognized(handle)
        flow = next((f for f in flows if f.get("flow_id") == flow_id), None)
        if flow is None:
            return (f"inspect_decoded_evidence: no flow {flow_id} in the "
                    f"capture ({len(flows)} flow(s))")
        if msg_idx is None:
            return _flow_detail(capture, flow)
        msgs = flow.get("messages") or []
        if not 1 <= msg_idx <= len(msgs):
            return (f"inspect_decoded_evidence: flow {flow_id} has "
                    f"{len(msgs)} message(s); no message {msg_idx}")
        return _n2_message_view(flow_id, msg_idx, msgs[msg_idx - 1])
    return _unrecognized(handle)


def inspect_decoded_evidence(capture: DecodedCapture, handle: str) -> str:
    """The Action's observation for one Evidence handle."""
    try:
        h = handle.strip()
        if h == "kpis":
            return _kpis_view(capture)
        if h == "flows":
            return _flows_listing(capture)
        if h == "unassociated":
            return _unassociated_listing(capture)
        if h == "n4":
            if capture.n4 is None:
                return "inspect_decoded_evidence: no N4 capture loaded"
            return _n4_listing(capture)
        if h == "sbi":
            if capture.sbi is None:
                return "inspect_decoded_evidence: no SBI capture loaded"
            return _sbi_listing(capture)
        if h.startswith("flow:"):
            return _dispatch_flow(capture, h)
        if h.startswith("unassociated:"):
            return _dispatch_indexed(capture.n2.get("unassociated") or [],
                                     "unassociated", h, _unassociated_view)
        if h.startswith("n4:"):
            if capture.n4 is None:
                return "inspect_decoded_evidence: no N4 capture loaded"
            msgs = capture.n4.get("messages") or []
            return _dispatch_indexed(msgs, "n4", h,
                                     lambda i, m: _n4_view(i, m, msgs))
        if h.startswith("sbi:"):
            if capture.sbi is None:
                return "inspect_decoded_evidence: no SBI capture loaded"
            return _dispatch_indexed(capture.sbi.get("messages") or [],
                                     "sbi", h, _sbi_view)
        return _unrecognized(handle)
    except Exception as exc:  # ADR-0001: degrade, never kill the search
        return (f'inspect_decoded_evidence: couldn\'t inspect "{handle}" '
                f"({exc})")
