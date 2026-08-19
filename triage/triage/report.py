"""Post-incident report writer: deterministic Markdown over a triage run.

ADR-0004: the only LLM prose in a report is the Episode's narrative — the
finalize step already wrote it. This module assembles, verifies, and
formats everything else: incident headers, [verified] evidence (re-checked
against the decode via grounded_evidence — the same completeness-bar
semantics the search enforced), spec-graph context blocks (ADR-0003), the
flow timeline, capture KPIs, the winning search trajectory, and the
memory-write note.

Two CLI paths share this module: `triage analyze --report` writes it
in-process, and the standalone `triage report` subcommand re-renders it
from a saved results file plus the decode — offline, no Groq, re-runnable.
Saved results degrade gracefully: every key is read with .get(), so files
written before the writer existed render with honest not-recorded lines.

The renderer never raises: a malformed saved result, a missing flow, or a
broken spec graph all degrade to explicit placeholders (ADR-0001).
"""

from pathlib import Path

from triage.evidence import DecodedCapture, fmt_ts
from triage.memory import Episode
from triage.search import grounded_evidence

MAX_SPEC_BLOCKS = 6
KPI_ORDER = ("attach_time_ms", "pdu_session_time_ms",
             "procedure_success_rate", "procedure_successes",
             "procedure_failures")


def load_graph() -> object | None:
    """A SpecGraph over the committed corpus, or None on any failure."""
    try:
        from triage.specgraph import SpecGraph
        return SpecGraph()
    except Exception:
        return None


def build_report(results: list[dict], capture: DecodedCapture,
                 graph=None) -> str:
    """The Markdown report for one saved triage run (see module docstring)."""
    if not results:
        return ("# Post-incident report — no incidents\n\n"
                "No failed Incidents to report.\n")
    if len(results) == 1:
        return _single_report(results[0], capture, graph)
    return _multi_report(results, capture, graph)


def write_report(results: list[dict], capture: DecodedCapture, path,
                 graph=None) -> None:
    """Render and write the report; OSError propagates to the CLI."""
    Path(path).write_text(build_report(results, capture, graph),
                          encoding="utf-8")


def _episode_parts(result: dict) -> tuple[Episode | None, dict | None]:
    """The validated Episode plus the raw dict, for honest degradation."""
    raw = result.get("episode")
    if not isinstance(raw, dict):
        return None, None
    try:
        return Episode.model_validate(raw), raw
    except Exception:
        return None, raw


def _incident_type(episode: Episode | None, raw: dict | None) -> str | None:
    if episode is not None:
        return episode.incident_type
    return raw.get("incident_type") if raw else None


def _flow_label(result: dict) -> str:
    """The flow identity for display: "{plane} — {procedure}" for SBI/N4
    results (they carry no N2 flow), "flow {id}" otherwise."""
    if result.get("plane") in ("sbi", "n4"):
        return f"{result['plane'].upper()} — " \
               f"{result.get('procedure') or 'unknown'}"
    return f"flow {result.get('flow_id')}"


def _header_lines(result: dict, episode, raw) -> list[str]:
    incident_type = _incident_type(episode, raw)
    flow_id = result.get("flow_id")
    lines = []
    if incident_type is None:
        lines.append(f"# Post-incident report — no hypothesis "
                     f"({_flow_label(result)})")
    else:
        lines.append(f"# Post-incident report — {incident_type}")
    lines.append("")
    if result.get("plane") in ("sbi", "n4"):
        lines.append(f"**Flow:** {_flow_label(result)}, "
                     f"{result.get('shape') or 'unknown'}")
    else:
        lines.append(f"**Flow:** {flow_id} — "
                     f"{result.get('procedure') or 'unknown'}, "
                     f"{result.get('shape') or 'unknown'}")
    if result.get("detail"):
        lines.append(f"**Incident detail:** {result['detail']}")
    if incident_type is not None:
        lines.append(f"**Hypothesis:** {incident_type} "
                     f"(reward {result.get('reward', 0.0)}, "
                     f"{result.get('rollouts', 0)} rollouts)")
    return lines


def _single_report(result: dict, capture: DecodedCapture, graph) -> str:
    episode, raw = _episode_parts(result)
    lines = _header_lines(result, episode, raw)
    lines.append("")
    lines += _sections(result, capture, graph, episode, raw,
                       result.get("flow_id"), h=2)
    return "\n".join(lines).rstrip("\n") + "\n"


def _multi_report(results: list[dict], capture: DecodedCapture, graph) -> str:
    lines = [f"# Post-incident report — {len(results)} incidents", "",
             "| # | flow | hypothesis | reward | rollouts |",
             "|---|------|------------|--------|----------|"]
    for i, result in enumerate(results, 1):
        episode, raw = _episode_parts(result)
        # the cell stays the bare id for N2 flows; SBI/N4 results name
        # their service / PFCP procedure instead
        cell = (_flow_label(result) if result.get("plane") in ("sbi", "n4")
                else result.get("flow_id"))
        lines.append(f"| {i} | {cell} | "
                     f"{_incident_type(episode, raw) or '—'} | "
                     f"{result.get('reward', 0.0)} | "
                     f"{result.get('rollouts', 0)} |")
    lines.append("")
    for i, result in enumerate(results, 1):
        episode, raw = _episode_parts(result)
        flow_id = result.get("flow_id")
        lines.append(f"## Incident {i} — "
                     f"{_incident_type(episode, raw) or 'no hypothesis'} "
                     f"— {_flow_label(result)}")
        lines.append("")
        if result.get("detail"):
            lines.append(f"**Incident detail:** {result['detail']}")
            lines.append("")
        lines += _sections(result, capture, graph, episode, raw, flow_id, h=3)
    return "\n".join(lines).rstrip("\n") + "\n"


def _sections(result: dict, capture: DecodedCapture, graph,
              episode: Episode | None, raw: dict | None,
              flow_id, h: int) -> list[str]:
    head = "#" * h
    lines = [f"{head} Root cause", _narrative(episode, raw), "",
             f"{head} Evidence"]
    cited = list(_cited_items(capture, episode, raw))
    if cited:
        for message, cause, ts, verified in cited:
            line = f"- [{'verified' if verified else 'unverified'}] " \
                   f"{message or '?'}"
            if ts is not None:
                line += f" @ {fmt_ts(ts)}s"
            if cause is not None:
                line += f" — cause #{cause}"
            lines.append(line)
    else:
        lines.append("(none cited)")
    lines.append("")
    spec_lines = _spec_section(graph, episode)
    if spec_lines:
        lines += [f"{head} Spec context"] + spec_lines + [""]
    if result.get("plane") == "sbi":
        lines += [f"{head} Timeline (SBI)"]
        lines += _sbi_timeline_lines(capture)
    elif result.get("plane") == "n4":
        lines += [f"{head} Timeline (N4)"]
        lines += _n4_timeline_lines(capture)
    else:
        lines += [f"{head} Timeline (flow {flow_id})"]
        lines += _timeline_lines(capture, flow_id)
    lines += ["", f"{head} Capture KPIs", _kpi_line(capture), "",
              f"{head} Search path"] + _search_path_lines(result) + ["",
              f"{head} Memory", _memory_line(result, episode), ""]
    return lines


def _narrative(episode: Episode | None, raw: dict | None) -> str:
    if episode is not None:
        return episode.narrative
    if raw and raw.get("narrative"):
        return raw["narrative"]
    return "No hypothesis: the LATS search completed no finalize."


def _cited_items(capture: DecodedCapture, episode: Episode | None,
                 raw: dict | None):
    """(message, cause, ts, verified) per cited evidence item.

    Degrades to the raw dict when the Episode does not validate; those
    items are never marked verified.
    """
    if episode is not None:
        verified = grounded_evidence(capture, episode)
        for ev in episode.cited_evidence:
            yield ev.message, ev.cause, ev.ts, ev in verified
    elif raw:
        for item in raw.get("cited_evidence") or []:
            if isinstance(item, dict):
                yield (item.get("message"), item.get("cause"),
                       item.get("ts"), False)


def _protocol_of(message: str) -> str | None:
    """The NAS/PFCP protocol a decoder message name carries, if any.

    NGAP names (e.g. InitialContextSetupRequest) carry no prefix and their
    causes are ENUMERATED-only, so they skip the cause query.
    """
    upper = (message or "").upper()
    for proto in ("5GMM", "5GSM", "PFCP"):
        if proto in upper:
            return proto
    return None


def _cause_query(proto: str | None, code: int) -> str | None:
    """The resolve() query for a cause code, or None when it can't resolve.

    The protocol prefix disambiguates shared values (e.g. 67 lives in both
    the 5GMM and 5GSM tables).
    """
    if proto not in ("5GMM", "5GSM", "PFCP"):
        return None
    return f"{proto} cause #{code}"


def _spec_section(graph, episode: Episode | None) -> list[str] | None:
    """Spec-graph entity blocks for the cited evidence, or None.

    Cause blocks first, then the message block per evidence item, deduped
    by entity id, capped at MAX_SPEC_BLOCKS. Any graph or resolve failure
    skips that block; a wholly-failed section is omitted.
    """
    if graph is None or episode is None:
        return None
    blocks, seen = [], set()
    for ev in episode.cited_evidence:
        queries = []
        if ev.cause is not None:
            query = _cause_query(_protocol_of(ev.message), ev.cause)
            if query is not None:
                queries.append(query)
        queries.append(ev.message)
        for query in queries:
            try:
                ref = graph.resolve(query)
            except Exception:
                ref = None
            if ref is None or ref.id in seen:
                continue
            seen.add(ref.id)
            try:
                blocks.append(graph.entity_block(ref))
            except Exception:
                continue
    if not blocks:
        return None
    lines = []
    for block in blocks[:MAX_SPEC_BLOCKS]:
        lines += block
        lines.append("")
    if len(blocks) > MAX_SPEC_BLOCKS:
        lines.append(f"… and {len(blocks) - MAX_SPEC_BLOCKS} more")
    return lines


def _timeline_lines(capture: DecodedCapture, flow_id) -> list[str]:
    """The flow's messages in order, with their cause codes."""
    flow = next((f for f in capture.n2.get("flows") or []
                 if f.get("flow_id") == flow_id), None)
    if flow is None:
        return [f"(flow {flow_id} not found in this capture)"]
    lines = []
    for i, msg in enumerate(flow.get("messages") or [], 1):
        name = msg.get("nas_inner") or msg.get("nas") or msg.get("ngap") or "?"
        line = f"[{i}] {fmt_ts(msg.get('ts'))}s  {name}"
        cause = msg.get("nas_cause")
        if cause:
            line += f"  cause #{cause.get('code')} ({cause.get('name')})"
        lines.append(line)
    if len(lines) > 50:
        lines = lines[:50] + [f"... ({len(lines) - 50} more not shown)"]
    return lines


def _sbi_timeline_lines(capture: DecodedCapture) -> list[str]:
    """The SBI messages in order; each request shows the status its
    response carried ("no response" when the capture ended unanswered),
    each response its status. The [i] indices match the sbi:<i> handles."""
    msgs = (capture.sbi or {}).get("messages") or []
    if not msgs:
        return ["(no SBI messages in this capture)"]
    # responses by their (src, dst, stream): a request finds its answer on
    # the flipped connection tuple
    responses = {(m.get("src_ip"), m.get("src_port"),
                  m.get("dst_ip"), m.get("dst_port"),
                  m.get("stream_id")): m
                 for m in msgs if m.get("direction") == "response"}
    lines = []
    for i, msg in enumerate(msgs, 1):
        line = f"[{i}] {fmt_ts(msg.get('ts'))}s  "
        if msg.get("direction") == "request":
            rsp = responses.get((msg.get("dst_ip"), msg.get("dst_port"),
                                 msg.get("src_ip"), msg.get("src_port"),
                                 msg.get("stream_id")))
            status = rsp.get("status") if rsp is not None else None
            outcome = str(status) if status is not None else "no response"
            line += f"{msg.get('method') or '?'} {msg.get('path') or '?'} " \
                    f"-> {outcome}"
        else:
            status = msg.get("status")
            line += f"-> {status if status is not None else '?'}"
        line += f"  ({msg.get('name') or '?'})"
        lines.append(line)
    return lines


def _n4_timeline_lines(capture: DecodedCapture) -> list[str]:
    """The N4 messages in order; each request shows the cause its response
    carried ("no response" when the capture ended unanswered, "answered"
    when the response carried no cause -- heartbeats carry none), each
    response its cause. The [i] indices match the n4:<i> handles."""
    msgs = (capture.n4 or {}).get("messages") or []
    if not msgs:
        return ["(no N4 messages in this capture)"]
    # responses by their (src, dst, seq): a request finds its answer on
    # the flipped tuple under the same sequence number
    responses = {(m.get("src_ip"), m.get("src_port"),
                  m.get("dst_ip"), m.get("dst_port"),
                  m.get("seq")): m
                 for m in msgs if " Response" in (m.get("name") or "")}
    lines = []
    for i, msg in enumerate(msgs, 1):
        name = msg.get("name") or "?"
        line = f"[{i}] {fmt_ts(msg.get('ts'))}s  "
        if " Request" in name:
            rsp = responses.get((msg.get("dst_ip"), msg.get("dst_port"),
                                 msg.get("src_ip"), msg.get("src_port"),
                                 msg.get("seq")))
            if rsp is None:
                outcome = "no response"
            else:
                outcome = rsp.get("cause") or "answered"
            line += f"{name} -> {outcome}"
        else:
            cause = msg.get("cause")
            line += f"-> {cause if cause is not None else '?'} ({name})"
        lines.append(line)
    return lines


def _kpi_line(capture: DecodedCapture) -> str:
    """The capture KPIs in a fixed curated order, as stored."""
    kpis = capture.n2.get("kpis") or {}
    present = [f"{key}: {kpis[key]}" for key in KPI_ORDER if key in kpis]
    return " | ".join(present) if present else "(no KPIs in this capture)"


def _first_line(text: str) -> str:
    """The first line of an observation, truncated at 78 columns."""
    line = text.split("\n", 1)[0]
    return line if len(line) <= 78 else line[:77] + "…"


def _search_path_lines(result: dict) -> list[str]:
    """The saved winning trajectory, one line per action."""
    if "trajectory" not in result:
        return ["(trajectory not recorded in this results file)"]
    trajectory = result.get("trajectory") or []
    if not trajectory:
        return ["(no trajectory — the search exhausted its rollouts)"]
    lines = []
    for i, pair in enumerate(trajectory, 1):
        action = pair[0]
        observation = _first_line(pair[1] or "") if len(pair) > 1 else ""
        lines.append(f"[{i}] {action} -> {observation}" if observation
                     else f"[{i}] {action}")
    return lines


def _memory_line(result: dict, episode: Episode | None) -> str:
    if episode is None:
        return "no Episode written (no hypothesis)"
    if result.get("memory_wrote"):
        return f"new Episode written ({episode.incident_type})"
    return (f"Episode already recorded ({episode.incident_type}) "
            f"— not rewritten")
