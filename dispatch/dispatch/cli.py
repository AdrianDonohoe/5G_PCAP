"""dispatch CLI: event-driven incident orchestration.

Each invocation is a fresh process: `handle` runs one Alarm event through
the Dispatcher and checkpoints at the approval interrupt; `approve` /
`reject` resume that checkpoint from the sqlite store; `close` finishes
an approved-executed incident with its Outcome and drafts a Runbook
proposal when the remediation worked and no committed Runbook covers the
signature; `detect-kpi` compares capture KPIs against the Golden baseline
and emits an Alarm event (source: kpi) when degraded, nothing when
healthy.
"""

import argparse
import json
import sys
from pathlib import Path

from .evidence import AlarmEvent
from .graph import build_graph, run_approval, run_to_approval
from .kpi import detect_kpi
from .learning import (confirmation_check, diff_new_file,
                       matching_runbook, outcome_section, write_draft)
from .memory import EpisodeStore
from .runbook import load_runbooks

REPO_ROOT = Path(__file__).resolve().parents[2]
STATE_PATH = REPO_ROOT / "dispatch" / "state" / "checkpoints.sqlite"
RECORDS_DIR = REPO_ROOT / "dispatch" / "records"
RUNBOOKS_DIR = REPO_ROOT / "dispatch" / "runbooks"
PROPOSED_RUNBOOKS_DIR = REPO_ROOT / "dispatch" / "runbooks" / "proposed"
SANDBOX_ROOT = REPO_ROOT / "sandbox"


def _graph():
    # The Episode store lives beside the checkpointer, so both resume
    # artifacts follow the same state dir (and the same test patch).
    # The runbooks are the committed procedural memory — parsed once per
    # invocation (and the same test patch keeps the CLI tests hermetic).
    episodes = EpisodeStore(STATE_PATH.parent / "episodes.jsonl")
    return build_graph(STATE_PATH, RECORDS_DIR, SANDBOX_ROOT,
                       episodes=episodes,
                       runbooks=load_runbooks(RUNBOOKS_DIR))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="dispatch",
        description="Incident orchestration for the NetCortex stack",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    handle = sub.add_parser(
        "handle", help="run one Alarm event through the Dispatcher")
    handle.add_argument("event", help="path to an Alarm event JSON file")
    handle.add_argument("--stub", help="path to the stubbed agent outputs JSON")

    approve = sub.add_parser(
        "approve",
        help="resume a checkpointed incident and dry-run or apply its proposal")
    approve.add_argument("incident_id")
    approve.add_argument("--execute", action="store_true",
                         help="apply the proposal's commands")

    reject = sub.add_parser(
        "reject", help="resume a checkpointed incident and record the rejection")
    reject.add_argument("incident_id")

    close = sub.add_parser(
        "close",
        help="close an approved-executed incident with its Outcome")
    close.add_argument("incident_id")
    close.add_argument("--outcome", choices=["resolved", "unresolved"],
                       required=True, help="the operator's verdict")
    close.add_argument("--evidence",
                       help="operator evidence for the verdict")

    detect = sub.add_parser(
        "detect-kpi", help="compare capture KPIs against the Golden baseline")
    detect.add_argument("capture", help="path to an N2 capture (pcap)")
    detect.add_argument("--sbi", help="path to the SBI capture (pcap)")
    detect.add_argument("--n4", help="path to the N4 capture (pcap)")

    args = ap.parse_args(argv if argv is not None else sys.argv[1:])
    try:
        if args.cmd == "handle":
            return _handle(args)
        if args.cmd == "approve":
            result = run_approval(_graph(), args.incident_id, "approve",
                                  execute=args.execute)
            for line in result.get("execution_log", []):
                print(line)
            return 0
        if args.cmd == "reject":
            result = run_approval(_graph(), args.incident_id, "reject")
            for line in result.get("execution_log", []):
                print(line)
            return 0
        if args.cmd == "close":
            return _close(args)
        return _detect_kpi(args)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _handle(args) -> int:
    if not args.stub:
        print("error: --stub is required (stubbed agent outputs JSON)",
              file=sys.stderr)
        return 1
    event = json.loads(Path(args.event).read_text())
    alarm = AlarmEvent.model_validate(event)
    record = RECORDS_DIR / f"{alarm.incident_id}.md"
    if record.exists():
        print(f"error: incident {alarm.incident_id} already has a record",
              file=sys.stderr)
        return 1
    stub = json.loads(Path(args.stub).read_text())
    run_to_approval(_graph(), alarm.model_dump(), stub)
    print(f"checkpointed — awaiting approval: "
          f"dispatch approve {alarm.incident_id}")
    return 0


def _close(args) -> int:
    """Close an approved-executed incident (spec #33): the checkpoint
    resume path of approve/reject, but with no graph step — the gates
    mirror run_approval's messages, the Outcome lands in the Episode and
    the Incident Record, and a resolved remediation with no matching
    committed Runbook drafts one deterministically for manual promotion.
    Every failure before the record append leaves close retryable."""
    cg = _graph()
    config = {"configurable": {"thread_id": args.incident_id}}
    snapshot = cg.get_state(config)
    if snapshot.next == () and not snapshot.values:
        raise ValueError(f"no checkpoint for incident {args.incident_id}")
    if snapshot.next != ():
        raise ValueError(f"incident {args.incident_id} is not awaiting "
                         "approval — approve or reject it first")
    state = snapshot.values
    if state.get("decision") != "approve" or not state.get("execute"):
        raise ValueError(f"incident {args.incident_id} was not approved "
                         "for execution — only approved-executed "
                         "incidents can be closed")
    record_path = RECORDS_DIR / f"{args.incident_id}.md"
    record = record_path.read_text()
    if "## Outcome" in record:
        raise ValueError(f"incident {args.incident_id} is already closed")
    episode = EpisodeStore(STATE_PATH.parent / "episodes.jsonl") \
        .set_outcome(args.incident_id, args.outcome, evidence=args.evidence)
    check = confirmation_check({"action": episode.action,
                                "args": episode.args or {}},
                               state.get("event") or {}, SANDBOX_ROOT)
    draft_lines = []
    if args.outcome == "resolved" and episode.action \
            and episode.action != "observe_only" \
            and not matching_runbook(load_runbooks(RUNBOOKS_DIR), episode):
        draft = write_draft(episode, PROPOSED_RUNBOOKS_DIR)
        draft_lines = ["Runbook draft staged for manual promotion "
                       "(deterministic template — no LLM call):",
                       diff_new_file(draft.read_text(), str(draft))]
    record_path.write_text(record + outcome_section(
        args.outcome, args.evidence, check))
    print(f"Suggested confirmation check: {check}")
    for line in draft_lines:
        print(line)
    print(f"closed incident {args.incident_id} as {args.outcome}")
    return 0


def _detect_kpi(args) -> int:
    captures = {"n2": args.capture}
    if args.sbi:
        captures["sbi"] = args.sbi
    if args.n4:
        captures["n4"] = args.n4
    event = detect_kpi(captures)
    if event is not None:
        AlarmEvent.model_validate(event)
        print(json.dumps(event, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
