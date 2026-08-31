"""The Incident Manager graph: the tracer spine of the dispatch layer.

Deterministic pipeline: gather (validated event + stubbed evidence) →
pcap agent (triage analyze over the decode, evidence grounded in the
decode inventory, replacing the stub's pcap items) → kpi agent (real KPI
evidence from 5gcap, replacing the stub's kpi items) → log agent (docker
stdout logs for the window, LLM-extracted evidence grounded to exact log
lines, replacing the stub's log items) → correlate → investigate (the
LATS root-cause search over the correlated inventory, triage's Tree
imported as a library, replacing the stub's narrative) → propose (LLM
selection from the fixed five-action vocabulary with a drafted
justification, commands rendered by the Executor's deterministic
templates, hash) → approval interrupt → execute on resume. Checkpointed
to sqlite, so approve/reject resume in a fresh process. The specialists'
subprocesses, the log extraction, the root-cause search and the proposal
selection run behind stub seams (ADR-0002); an invalid selection yields
no proposal, and the record says so honestly."""

import re
import sqlite3
from pathlib import Path
from typing import TypedDict

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from .correlation import link
from .evidence import AlarmEvent, EvidenceItem
from .executor import Executor, OBSERVE_ONLY_NOTE, proposal_hash
from .kpi import run_kpi_agent
from .log import run_log_agent
from .memory import Episode, EvidenceKey
from .pcap import run_pcap_agent
from .proposal import run_proposal
from .record import render_record
from .root_cause import run_root_cause

_HASH_RE = re.compile(r"Proposal hash: `([0-9a-f]+)`")


class State(TypedDict, total=False):
    event: dict
    stub: dict
    evidence: list
    links: list
    root_cause: str
    proposal: dict | None
    record_path: str
    decision: str
    execute: bool
    approval: str
    execution_log: list


def _config(incident_id: str) -> dict:
    return {"configurable": {"thread_id": incident_id}}


def _replace_evidence(state: State, source: str, items: list) -> None:
    """Swap the stub evidence of one source for the specialist's real
    items; stub items of other sources stay until their node runs."""
    state["evidence"] = [e for e in state["evidence"]
                         if e["source"] != source] + items


def _validate_stub(stub: dict) -> dict:
    if "evidence" not in stub:
        raise ValueError("stub missing 'evidence'")
    return {
        "evidence": [EvidenceItem.model_validate(item).model_dump()
                     for item in stub["evidence"]],
    }


def _write_record(state: State, approval: str, log_lines: list[str]) -> None:
    state["approval"] = approval
    state["execution_log"] = state.get("execution_log", []) + log_lines
    Path(state["record_path"]).write_text(render_record({
        "event": state["event"],
        "evidence": state["evidence"],
        "links": state["links"],
        "root_cause": state["root_cause"],
        "proposal": state["proposal"],
        "approval": approval,
        "execution_log": state["execution_log"],
    }))


def _write_episode(state: State, decision: str, episodes) -> None:
    """The Episode write at decision time (spec #33): every decided
    incident is remembered, whatever the decision — the diagnosis stands
    even when the proposal was refused. The Outcome is appended later,
    at close. With no store injected, the memory path does nothing."""
    if episodes is None:
        return
    proposal = state["proposal"] or {}
    episodes.add(Episode(
        incident_id=state["event"]["incident_id"],
        procedure=state["event"].get("procedure"),
        scenario=state["event"].get("scenario"),
        evidence_keys=[EvidenceKey(key=key, value=value)
                       for item in state["evidence"]
                       for key, value in (item.get("keys") or {}).items()],
        causes=[item["cause"] for item in state["evidence"]
                if item.get("cause")],
        action=proposal.get("action"),
        args=proposal.get("args"),
        narrative=state["root_cause"],
        justification=proposal.get("justification"),
        decision=decision,
    ))


def _read_record_hash(path: str) -> str:
    match = _HASH_RE.search(Path(path).read_text())
    if not match:
        raise ValueError("proposal hash mismatch — the record has no hash")
    return match.group(1)


def build_graph(state_path, records_dir, sandbox_root, runner=None,
                kpi_runner=None, triage_runner=None, log_runner=None,
                extractor=None, search=None, proposer=None, episodes=None,
                runbooks=None):
    """Compile the Incident Manager graph with a sqlite checkpointer. The
    checkpointer's connection lives as long as the compiled graph.
    ``kpi_runner`` stubs the 5gcap subprocess in tests; ``triage_runner``
    stubs the triage analyze subprocess; ``log_runner`` stubs the docker
    compose logs subprocess and ``extractor`` the log extraction;
    ``search`` stubs the root-cause search (tests inject a canned search
    or a Tree with stub expand/evaluate — the spec's stub-injected Tree
    pattern); ``proposer`` stubs the proposal selection. ``episodes`` is
    the Episode store seam (spec #33): the investigate node seeds the
    objective from it and the execute node writes the decided Episode to
    it; ``runbooks`` is the procedural-memory seam (spec #33), the
    parsed committed Runbooks the propose node matches and prepends
    ahead of the proposer call; absent, the memory paths do nothing and
    behavior is exactly as before. Every live default stays behind its
    seam (ADR-0002: pytest never builds the Groq predictor); the store
    and the runbooks are pure file I/O, so tests inject tmp-backed
    stores and parsed Runbooks rather than stubs."""
    records_dir = Path(records_dir)
    records_dir.mkdir(parents=True, exist_ok=True)
    Path(state_path).parent.mkdir(parents=True, exist_ok=True)
    executor = Executor(sandbox_root, runner=runner)

    def gather(state: State) -> State:
        event = AlarmEvent.model_validate(state["event"])
        state["event"] = event.model_dump()
        state["stub"] = _validate_stub(state["stub"])
        state["evidence"] = state["stub"]["evidence"]
        state["record_path"] = str(records_dir / f"{event.incident_id}.md")
        return state

    def pcap_agent(state: State) -> State:
        captures = state["event"].get("captures") or {}
        _replace_evidence(state, "pcap",
                          run_pcap_agent(captures,
                                         triage_runner=triage_runner))
        return state

    def kpi_agent(state: State) -> State:
        captures = state["event"].get("captures") or {}
        _replace_evidence(state, "kpi",
                          run_kpi_agent(captures, runner=kpi_runner))
        return state

    def log_agent(state: State) -> State:
        _replace_evidence(state, "log",
                          run_log_agent(state["event"], sandbox_root,
                                        log_runner=log_runner,
                                        extractor=extractor))
        return state

    def correlate(state: State) -> State:
        window = state["event"]["time_window"]
        state["links"] = link(state["evidence"],
                              (window["start"], window["end"]))
        return state

    def investigate(state: State) -> State:
        state["root_cause"] = run_root_cause(
            state["event"], state["evidence"], state["links"], search=search,
            episodes=episodes)
        return state

    def propose(state: State) -> State:
        proposal = run_proposal(state["event"], state["root_cause"],
                                proposer=proposer, runbooks=runbooks,
                                evidence=state["evidence"])
        if proposal is not None:
            try:
                proposal["commands"] = executor.dry_run(proposal)
            except ValueError:
                # The Executor's render rail rejected the args (unknown
                # nf, path escape, bad IMSI, unknown scenario): an
                # invalid selection yields no proposal, like the
                # vocabulary check.
                proposal = None
        if proposal is not None:
            proposal["hash"] = proposal_hash(proposal)
        state["proposal"] = proposal
        _write_record(state, "pending", [])
        return state

    def approval(state: State) -> State:
        payload = interrupt({"pending": True})
        state["decision"] = payload["decision"]
        state["execute"] = bool(payload.get("execute", False))
        return state

    def execute(state: State) -> State:
        proposal = state["proposal"]
        if proposal is None and state["decision"] != "reject":
            raise ValueError("no proposal was produced — nothing to execute")
        if proposal is not None and \
                _read_record_hash(state["record_path"]) != proposal["hash"]:
            raise ValueError("proposal hash mismatch — the record was edited")
        if state["decision"] == "reject":
            _write_record(state, "rejected",
                          ["rejected: no commands applied"])
            _write_episode(state, "rejected", episodes)
            return state
        commands = [c for c in proposal["commands"]
                    if c != OBSERVE_ONLY_NOTE]
        log = ([f"dry-run: {c}" for c in commands]
               or [f"dry-run: {OBSERVE_ONLY_NOTE}"])
        if state["execute"]:
            executor.apply(proposal, commands)
            log += [f"executed: {c}" for c in commands]
            _write_record(state, "approved-executed", log)
        else:
            _write_record(state, "approved-dry-run", log)
        _write_episode(state,
                       "approved-executed" if state["execute"]
                       else "approved-dry-run", episodes)
        return state

    graph = StateGraph(State)
    graph.add_node("gather", gather)
    graph.add_node("pcap_agent", pcap_agent)
    graph.add_node("kpi_agent", kpi_agent)
    graph.add_node("log_agent", log_agent)
    graph.add_node("correlate", correlate)
    graph.add_node("investigate", investigate)
    graph.add_node("propose", propose)
    graph.add_node("approval", approval)
    graph.add_node("execute", execute)
    graph.add_edge(START, "gather")
    graph.add_edge("gather", "pcap_agent")
    graph.add_edge("pcap_agent", "kpi_agent")
    graph.add_edge("kpi_agent", "log_agent")
    graph.add_edge("log_agent", "correlate")
    graph.add_edge("correlate", "investigate")
    graph.add_edge("investigate", "propose")
    graph.add_edge("propose", "approval")
    graph.add_edge("approval", "execute")
    graph.add_edge("execute", END)
    conn = sqlite3.connect(str(state_path), check_same_thread=False)
    return graph.compile(checkpointer=SqliteSaver(conn))


def run_to_approval(cg, event: dict, stub: dict):
    """Run a new Alarm event through the graph to the approval interrupt."""
    return cg.invoke({"event": event, "stub": stub},
                     _config(event["incident_id"]))


def run_approval(cg, incident_id: str, decision: str,
                 execute: bool = False):
    """Resume a checkpointed incident with an approval decision."""
    if decision not in ("approve", "reject"):
        raise ValueError(f"unknown decision {decision!r}")
    config = _config(incident_id)
    snapshot = cg.get_state(config)
    if snapshot.next == () and not snapshot.values:
        raise ValueError(f"no checkpoint for incident {incident_id}")
    if snapshot.next == ():
        raise ValueError(f"incident {incident_id} is not awaiting approval")
    return cg.invoke(Command(resume={"decision": decision,
                                     "execute": execute}), config)
