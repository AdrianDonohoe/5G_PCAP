"""dispatch CLI: event-driven incident orchestration.

Each invocation is a fresh process: `handle` runs one Alarm event through
the Dispatcher and checkpoints at the approval interrupt; `approve` /
`reject` resume that checkpoint from the sqlite store; `detect-kpi`
compares capture KPIs against the Golden baseline and emits an Alarm
event (source: kpi) when degraded, nothing when healthy.
"""

import argparse
import json
import sys
from pathlib import Path

from .evidence import AlarmEvent
from .graph import build_graph, run_approval, run_to_approval
from .kpi import detect_kpi
from .memory import EpisodeStore

REPO_ROOT = Path(__file__).resolve().parents[2]
STATE_PATH = REPO_ROOT / "dispatch" / "state" / "checkpoints.sqlite"
RECORDS_DIR = REPO_ROOT / "dispatch" / "records"
SANDBOX_ROOT = REPO_ROOT / "sandbox"


def _graph():
    # The Episode store lives beside the checkpointer, so both resume
    # artifacts follow the same state dir (and the same test patch).
    episodes = EpisodeStore(STATE_PATH.parent / "episodes.jsonl")
    return build_graph(STATE_PATH, RECORDS_DIR, SANDBOX_ROOT,
                       episodes=episodes)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="dispatch",
        description="Incident orchestration for the 5G_PCAP stack",
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
