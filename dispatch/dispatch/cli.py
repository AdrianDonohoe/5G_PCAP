"""dispatch CLI: event-driven incident orchestration.

The subcommands are the Dispatcher's public interface, reserved here so the
--help surface is stable while the behavior behind each lands in later
slices: `handle` runs one Alarm event through the Dispatcher, `detect-kpi`
compares capture KPIs against the Golden baseline, and `approve`/`reject`
resume a checkpointed incident across invocations.
"""

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="dispatch",
        description="Incident orchestration for the 5G_PCAP stack",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("handle", help="run one Alarm event through the Dispatcher")
    sub.add_parser("detect-kpi", help="compare capture KPIs against the Golden baseline")
    sub.add_parser("approve", help="resume a checkpointed incident and dry-run or apply its proposal")
    sub.add_parser("reject", help="resume a checkpointed incident and record the rejection")
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])
    print(f"dispatch {args.cmd}: not implemented yet", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
