"""triage CLI: one LATS search per failed Incident in a decoded capture,
plus a deterministic post-incident report writer (ADR-0004).

ADR-0002: a separate CLI consuming 5gcap's --json decode output (the
decoded Capture of CONTEXT.md) — decoding stays a 5gcap step. Hypotheses
print to stdout as a JSON array; `triage report` re-renders a saved run
(`triage analyze --out`) as Markdown, offline and without Groq. Both
print only their payload to stdout — progress and memory notes go to
stderr, so stdout stays machine-readable. Zero Incidents is a successful
empty result (exit 0); exit 1 means the invocation itself failed.

GROQ_API_KEY must be set for any live `triage analyze` invocation
(ADR-0002: no local-model fallback); a missing key surfaces as an honest
error before any search starts. Mid-search LLM failures degrade inside
the tree by design. `triage report` never needs it.
"""

import argparse
import json
import sys
from pathlib import Path

from triage.evidence import load_capture
from triage.incidents import detect_incidents
from triage.memory import MemoryStore, consolidate
from triage.report import build_report, load_graph, write_report
from triage.search import run_lats


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="triage",
        description="LLM-agent root-cause hypotheses for failed 5G "
                    "Registration / PDU Session procedures.")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser(
        "analyze",
        help="one LATS search per failed Incident in a decoded capture",
        description="Consumes 5gcap's --json decode output (N2; optionally "
                    "N4 with --n4).")
    analyze.add_argument("n2_json", help="5gcap --json decode output (N2)")
    analyze.add_argument("--n4", metavar="N4.json",
                         help="optional 5gcap N4 decode output")
    analyze.add_argument("--flow", type=int,
                         help="only triage Incidents in this flow")
    analyze.add_argument("--episodes-path", metavar="PATH",
                         help="episodic memory store override (default: "
                              "triage/memory/episodes.jsonl)")
    analyze.add_argument("--out", metavar="PATH",
                         help="also write the JSON results to this file")
    analyze.add_argument("--report", metavar="PATH",
                         help="also write the post-incident Markdown "
                              "report to this file")
    analyze.add_argument("--verbose", action="store_true",
                         help="print each winning Trajectory to stderr")
    report = sub.add_parser(
        "report",
        help="re-render a saved run as a post-incident Markdown report",
        description="Deterministic Markdown report (ADR-0004) from a "
                    "saved `triage analyze --out` results file plus the "
                    "decode — no Groq, no search, re-runnable offline.")
    report.add_argument("--results", metavar="R.json", required=True,
                        help="saved `triage analyze --out` results")
    report.add_argument("n2_json", help="5gcap --json decode output (N2)")
    report.add_argument("--n4", metavar="N4.json",
                        help="optional 5gcap N4 decode output")
    report.add_argument("-o", "--out", metavar="PATH",
                        help="also write the report to this file")
    return parser.parse_args(argv)


def _result(incident: dict, episode, result, wrote: bool) -> dict:
    return {
        "flow_id": incident.get("flow_id"),
        "procedure": incident.get("procedure"),
        "shape": incident.get("shape"),
        "detail": incident.get("detail"),
        "episode": episode.model_dump(mode="json") if episode else None,
        "reward": result.reward,
        "rollouts": result.rollouts,
        "trajectory": [[a, o] for a, o in result.trajectory],
        "memory_wrote": wrote,
    }


def _report(args: argparse.Namespace) -> int:
    """The `triage report` subcommand: re-render a saved run offline."""
    try:
        results = json.loads(Path(args.results).read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"triage: error: cannot load {args.results}: {exc}",
              file=sys.stderr)
        return 1
    if not isinstance(results, list):
        print(f"triage: error: {args.results} is not a JSON array of "
              f"results (as saved by `triage analyze --out`)",
              file=sys.stderr)
        return 1
    try:
        capture = load_capture(args.n2_json, args.n4)
    except Exception as exc:  # JSON/IO errors in the decode files
        print(f"triage: error: cannot load {args.n2_json}: {exc}",
              file=sys.stderr)
        return 1
    report_text = build_report(results, capture, graph=load_graph())
    if args.out:
        try:
            Path(args.out).write_text(report_text, encoding="utf-8")
        except OSError as exc:
            print(f"triage: error: cannot write {args.out}: {exc}",
                  file=sys.stderr)
            return 1
    sys.stdout.write(report_text)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.command == "report":
        return _report(args)
    try:
        capture = load_capture(args.n2_json, args.n4)
    except Exception as exc:  # JSON/IO errors in the decode files
        print(f"triage: error: cannot load {args.n2_json}: {exc}",
              file=sys.stderr)
        return 1
    store = MemoryStore(Path(args.episodes_path)) if args.episodes_path \
        else MemoryStore()
    incidents = detect_incidents(capture.n2)
    if args.flow is not None:
        incidents = [i for i in incidents if i.get("flow_id") == args.flow]

    if not incidents:
        print(f"triage: no failed Incidents detected in {args.n2_json} "
              f"({len(capture.n2.get('flows') or [])} flow(s))"
              + (f"; --flow {args.flow} matched none" if args.flow else ""),
              file=sys.stderr)
        results = []
    else:
        results = []
        for n, incident in enumerate(incidents, 1):
            print(f"[{n}/{len(incidents)}] flow {incident['flow_id']} "
                  f"{incident['procedure']} ({incident['shape']})",
                  file=sys.stderr)
            try:
                result = run_lats(capture, incident, store=store)
            except RuntimeError as exc:  # e.g. GROQ_API_KEY unset
                print(f"triage: error: {exc}", file=sys.stderr)
                return 1
            wrote = False
            episode = result.episode
            if episode is not None:
                episode, wrote = consolidate(episode, store)
                print("memory: new Episode written" if wrote else
                      "memory: duplicate of an existing Episode, not written",
                      file=sys.stderr)
            else:
                print("no hypothesis: the search completed no finalize",
                      file=sys.stderr)
            if episode is not None:
                print(f"hypothesis: {episode.incident_type} "
                      f"(reward={result.reward:.2f}, "
                      f"rollouts={result.rollouts})", file=sys.stderr)
            if args.verbose and result.trajectory:
                print("winning trajectory:", file=sys.stderr)
                for action, observation in result.trajectory:
                    print(f"  action: {action}", file=sys.stderr)
                    print(f"  observation: {observation}", file=sys.stderr)
            results.append(_result(incident, episode, result, wrote))

    payload = json.dumps(results, indent=2)
    if args.out:
        try:
            Path(args.out).write_text(payload + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"triage: error: cannot write {args.out}: {exc}",
                  file=sys.stderr)
            return 1
    if args.report:
        try:
            write_report(results, capture, Path(args.report),
                         graph=load_graph())
        except OSError as exc:
            print(f"triage: error: cannot write {args.report}: {exc}",
                  file=sys.stderr)
            return 1
    print(payload)
    return 0
