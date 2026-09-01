"""The dispatch eval harness: the ten sandbox failure-injection
scenarios run as Alarm events through the real pipeline against the live
lab, and a judge model distinct from the generator scores each Incident
Record's quality.

The run per scenario: capture.sh applies the failure and captures the
triple, the real detect-kpi CLI turns the captures into the Alarm event
(healthy KPIs produce no event — a reported detection miss, never a
fabricated one), and the merged 5gcap export becomes the judge's ground
brief. Each run then executes one fresh pipeline pass — the graph with
per-run state/records dirs, ending at the approval gate with the pending
Incident Record — and the judge scores the record against the decoded
facts only. The scenario label is ground truth for the report, never
judge input.

The judge is the Qwen 3.6-27b family against the gpt-oss-120b generator,
mirroring triage's harness: dspy is reconfigured to the judge's LM on
every call (the generator reconfigures dspy whenever it runs), the
scores are clamped to 0-1, and a judge failure degrades that run to 0.0
with an error comment — it never kills the harness. Judge and pipeline
defaults are lazy and key-guarded: importing this module never requires
GROQ_API_KEY or network.

The harness is the only runner that touches Groq (ADR-0002): pytest
never executes this file — the tests import it and stub the capture,
detect, analyze, pipeline and judge seams. The lab seams (capture.sh,
detect-kpi, 5gcap analyze, the pipeline) are likewise injectable so the
offline tests never spawn a subprocess."""

import argparse
import json
import os
import shlex
import subprocess
from pathlib import Path

import dspy

from dispatch.executor import SCENARIOS
from dispatch.graph import build_graph, run_to_approval
from dispatch.kpi import run_analyze

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "5gcap" / "tests" / "fixtures"
SANDBOX = REPO_ROOT / "sandbox"

# capture.sh's merged-eval naming exception: these scenarios write their
# N2 dump under the golden-style _n2 name — no unsuffixed pcap exists
# for the harness to read.
MERGED_SCENARIOS = ("pdu_session_rsp_timeout",)

DIMS = ("accuracy", "specificity", "evidence", "causality", "proposal")

# dspy treats the first segment of the model string as its provider and
# sends the rest; Groq's own model IDs carry an "openai/" vendor prefix,
# hence the doubled prefix (same trick as triage's harness). The judge
# family is deliberately distinct from the gpt-oss-120b generator.
JUDGE = ("openai/qwen/qwen3.6-27b", "https://api.groq.com/openai/v1")


class JudgeSignature(dspy.Signature):
    """You score an Incident Record produced by the dispatch pipeline
    against the decoded wire facts it was allowed to see. The record is
    the full markdown audit trail; the facts are a machine-written brief
    of the merged N2/N4/SBI decode. Score each dimension 0.0-1.0 and
    reply with JSON only.

    Dimensions:
    - accuracy: every claim in the record matches the decoded facts; no
      invented messages, causes or events. Honest admissions ("no
      evidence found") are accurate, not penalized.
    - specificity: the record names concrete messages, NAS/PFCP causes,
      SBI status codes, endpoints and timestamps instead of vague
      failure shapes.
    - evidence: every Evidence item carries a real citation — a log
      line, a decoded message, a KPI value — that actually appears in
      the facts.
    - causality: the root-cause narrative explains the observed failure
      coherently. For timeouts the missing terminal message IS the
      mechanism and retransmission bursts are evidence of silence, not
      a contradiction.
    - proposal: the chosen action addresses the root cause and the
      justification connects them. A record that honestly reports no
      proposal scores proposal 0.0.
    """
    record: str = dspy.InputField(desc="the full Incident Record "
                                       "markdown")
    facts: str = dspy.InputField(desc="the decoded wire facts (merged "
                                      "N2/N4/SBI brief)")
    scores: str = dspy.OutputField(desc='JSON {"accuracy": x, '
                                        '"specificity": x, '
                                        '"evidence": x, "causality": x, '
                                        '"proposal": x}')
    comment: str = dspy.OutputField(desc="one sentence explaining the "
                                         "scores")


def _clamp(value) -> float:
    """A judge output clamped to 0-1; unparseable values are 0.0."""
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def default_judge():
    """judge(record, facts) -> {"scores": {dim: float}, "comment": str},
    over JudgeSignature. Built lazily like default_propose: the LM
    builds on first use, so importing this module never requires
    GROQ_API_KEY or network (ADR-0002). dspy is reconfigured to the
    judge's LM on every call — the pipeline's generator reconfigures
    dspy whenever it runs. One retry, then the run degrades to 0.0 with
    an error comment; the harness never dies on judge failure."""
    def judge(record: str, facts: str) -> dict:
        key = os.environ.get("GROQ_API_KEY")
        if not key:
            raise RuntimeError("GROQ_API_KEY is not set (ADR-0002: no "
                               "local model fallback)")
        lm = dspy.LM(JUDGE[0], api_base=JUDGE[1], api_key=key,
                     cache=False, max_tokens=8192)
        dspy.configure(lm=lm)
        predictor = dspy.Predict(JudgeSignature)
        last = None
        for _ in range(2):
            try:
                result = predictor(record=record, facts=facts)
                scores = json.loads(result.scores)
                return {"scores": {d: _clamp(scores.get(d))
                                   for d in DIMS},
                        "comment": str(getattr(result, "comment", "") or "")}
            except Exception as exc:  # LLM failure modes are library-defined
                last = exc
        return {"scores": {d: 0.0 for d in DIMS},
                "comment": f"judge failed: {last}"}

    return judge


def _procedure_lines(procs, with_status=False) -> list:
    lines = []
    for proc in procs:
        line = f"  procedure {proc.get('kind')}: {proc.get('outcome')}"
        if with_status and proc.get("status") is not None:
            line += f", status {proc.get('status')}"
        lines.append(line)
    return lines


def _plane_lines(name, section, with_status=False) -> list:
    lines = [f"{name}:"]
    lines += _procedure_lines(section.get("procedures", []), with_status)
    lines.append(f"  unpaired_requests="
                 f"{section.get('unpaired_requests', 0)}")
    return lines


def brief(export: dict) -> str:
    """The judge's ground: the merged export reduced to its failure
    shapes per plane. Decoded facts only — the scenario label never
    reaches the judge."""
    lines = []
    for name, value in export.get("kpis", {}).items():
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            lines.append(f"KPI {name}={value}")
    for flow in export.get("flows", []):
        lines.append(f"Flow {flow.get('flow_id')}: "
                     f"partial={flow.get('partial')}")
        for msg in flow.get("messages", []):
            parts = [f"ts={msg.get('ts')}", str(msg.get("ngap") or ""),
                     str(msg.get("nas") or "")]
            cause = msg.get("nas_cause")
            if cause:
                parts.append(f"nas_cause {cause.get('code')}")
            lines.append("  " + " ".join(p for p in parts if p))
        lines += _procedure_lines(flow.get("procedures", []))
    n4 = export.get("n4")
    if n4:
        lines += _plane_lines("N4", n4)
    sbi = export.get("sbi")
    if sbi:
        lines += _plane_lines("SBI", sbi, with_status=True)
    return "\n".join(lines)


def capture_scenario(name: str) -> dict:
    """Capture one failure-injection scenario against the live sandbox:
    bash capture.sh --scenario <name>, then the pcaps and label it wrote
    into 5gcap/tests/fixtures."""
    command = (f"bash {shlex.quote(str(SANDBOX / 'capture.sh'))} "
               f"--scenario {shlex.quote(name)}")
    result = subprocess.run(command, shell=True, cwd=SANDBOX,
                            capture_output=True, text=True)
    if result.returncode != 0:
        detail = (result.stderr or "").strip()
        suffix = f": {detail}" if detail else ""
        raise RuntimeError(f"capture.sh {name} failed "
                           f"(exit {result.returncode}){suffix}")
    n2_name = (f"{name}_n2.pcap" if name in MERGED_SCENARIOS
               else f"{name}.pcap")
    captures = {"n2": str(FIXTURES / n2_name),
                "sbi": str(FIXTURES / f"{name}_sbi.pcap"),
                "n4": str(FIXTURES / f"{name}_n4.pcap")}
    label_path = FIXTURES / f"{name}.label.json"
    captures["label"] = json.loads(label_path.read_text())
    return captures


def detect_event(captures: dict) -> dict | None:
    """The real detect-kpi boundary: shell the CLI, parse the Alarm
    event JSON from its stdout. Healthy KPIs print nothing — a reported
    detection miss, never a fabricated event. A non-zero exit is a hard
    failure."""
    command = (f"uv run --project {shlex.quote(str(REPO_ROOT / 'dispatch'))} "
               f"dispatch detect-kpi {shlex.quote(captures['n2'])} "
               f"--sbi {shlex.quote(captures['sbi'])} "
               f"--n4 {shlex.quote(captures['n4'])}")
    result = subprocess.run(command, shell=True, capture_output=True,
                            text=True)
    if result.returncode != 0:
        detail = (result.stderr or "").strip()
        suffix = f": {detail}" if detail else ""
        raise RuntimeError(f"detect-kpi failed (exit {result.returncode})"
                           f"{suffix}")
    if not (result.stdout or "").strip():
        return None
    return json.loads(result.stdout)


def run_pipeline(event: dict, run_dir) -> str:
    """One fresh pipeline pass ending at the approval gate: a new graph
    over per-run state/records dirs (the CLI's fixed paths are its
    presentation; the graph is the pipeline), run to approval with the
    honest empty stub — every specialist replaces its section. Returns
    the pending record's markdown."""
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    graph = build_graph(run_dir / "checkpoints.sqlite",
                        run_dir / "records", SANDBOX)
    run_to_approval(graph, event, {"evidence": []})
    record = run_dir / "records" / f'{event["incident_id"]}.md'
    return record.read_text()


def run_scenario(name, runs, judge, work, resume=None, capture=None,
                 detect=None, analyze=None, pipeline=None) -> dict:
    """One scenario through the harness: capture once, detect the event
    once, decode once for the judge's ground, then per run a fresh
    pipeline pass and a judge call over (record, brief). ``resume`` is
    the scenario's checkpointed entry — a completed or partially
    completed run reuses its event and facts, never touching the lab; a
    missed or errored entry starts fresh. The capture, detect, analyze,
    pipeline and judge seams default to their live implementations and
    are injectable for the offline tests (ADR-0002)."""
    judge = judge or default_judge()
    capture = capture or capture_scenario
    detect = detect or detect_event
    analyze = analyze or run_analyze
    pipeline = pipeline or run_pipeline
    work = Path(work)
    if resume is not None and resume.get("event") is not None:
        entry = resume
        event, facts = entry["event"], entry["facts"]
    else:
        entry = {"scenario": name, "label": None, "event": None,
                 "runs": []}
        try:
            captures = capture(name)
            entry["label"] = captures.get("label")
            event = detect(captures)
            if event is None:      # healthy KPIs: a reported detection miss
                return entry
            facts = brief(analyze(captures))
            entry["facts"] = facts
        except Exception as exc:   # a down lab degrades per scenario
            entry["error"] = str(exc)
            return entry
        entry["event"] = event
    done = {r["run"] for r in entry["runs"] if "scores" in r}
    # Stale errored runs are retried below — drop them first so the
    # checkpoint never accumulates two entries for one run number. The
    # remaining runs stay in ascending order and the loop appends in
    # ascending order, so no re-sort is needed.
    entry["runs"] = [r for r in entry["runs"] if "scores" in r]
    for run in range(runs):
        if run in done:
            continue
        run_entry = {"run": run}
        try:
            run_dir = work / name / str(run)
            record = pipeline(event, run_dir)
            scores = judge(record, facts)
            run_entry.update(scores)
            run_entry["quality"] = round(
                sum(scores["scores"][d] for d in DIMS) / len(DIMS), 3)
            run_entry["record"] = record
        except Exception as exc:   # one bad pass never kills the scenario
            run_entry["error"] = str(exc)
        entry["runs"].append(run_entry)
    return entry


def _mean(runs, dim) -> float:
    return sum(r["scores"][dim] for r in runs) / len(runs)


def _aggregate(runs) -> tuple[float, str]:
    """The quality mean and per-dimension means over scored runs."""
    quality = round(sum(r["quality"] for r in runs) / len(runs), 2)
    dims = " ".join(f"{d} {_mean(runs, d):.2f}" for d in DIMS)
    return quality, dims


def _entry_line(entry) -> str:
    label = entry.get("label")
    label_txt = f" (label: {label['incident_type']})" if label else ""
    runs = [r for r in entry.get("runs", []) if "scores" in r]
    if entry.get("error"):
        return f"{entry['scenario']}: error: {entry['error']}"
    if entry.get("event") is None:
        return f"{entry['scenario']}{label_txt}: no event detected"
    if not runs:
        return (f"{entry['scenario']}{label_txt}: "
                f"{len(entry['runs'])} runs failed, no scores")
    quality, dims = _aggregate(runs)
    return (f"{entry['scenario']}{label_txt}: quality {quality:.2f} over "
            f"{len(runs)} runs — {dims}")


def report(results: list) -> str:
    """Per-scenario results with the ground-truth label as a reference
    column (never judge input), per-dimension means, misses and errors,
    and the overall means over every judged run."""
    lines = [_entry_line(e) for e in results]
    scored = [r for e in results
              for r in e.get("runs", []) if "scores" in r]
    if scored:
        quality, dims = _aggregate(scored)
        misses = sum(1 for e in results
                     if not e.get("error") and e.get("event") is None)
        errors = sum(1 for e in results if e.get("error"))
        lines.append(f"overall: quality {quality:.2f} over {len(scored)} "
                     f"judged runs ({misses} missed, {errors} error) — "
                     f"{dims}")
    return "\n".join(lines)


def checkpoint(out, results, summary=None) -> None:
    """Write {"summary": summary, "runs": results} — the resume contract.
    The summary is the final report text, written on the run's last
    checkpoint (mirroring triage's harness); mid-run writes carry None."""
    Path(out).write_text(json.dumps({"summary": summary, "runs": results},
                                    indent=2), encoding="utf-8")


def load_results(out) -> dict:
    """The checkpoint's runs, or an empty result set for a missing file."""
    path = Path(out)
    if not path.exists():
        return {"summary": None, "runs": []}
    data = json.loads(path.read_text())
    return {"summary": data.get("summary"),
            "runs": data.get("runs", [])}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Dispatch eval harness: the ten sandbox "
                    "failure-injection scenarios as Alarm events through "
                    "the real pipeline against the live lab, each record "
                    "judged by a model distinct from the generator.")
    parser.add_argument("--scenarios", nargs="*", default=None,
                        help="scenarios to run (default: all ten)")
    parser.add_argument("--runs", type=int, default=3,
                        help="pipeline runs per scenario (default: 3)")
    parser.add_argument("--out", type=Path,
                        default=Path(__file__).parent / "results.json",
                        help="results JSON (default: evals/results.json)")
    parser.add_argument("--work", type=Path,
                        default=Path(__file__).parent / "work",
                        help="per-run state/records dir (default: "
                             "evals/work)")
    parser.add_argument("--resume", action="store_true",
                        help="resume from --out: completed runs are "
                             "skipped, the lab is not re-captured")
    args = parser.parse_args(argv)
    scenarios = args.scenarios or list(SCENARIOS)
    results = (load_results(args.out)["runs"]
               if args.resume and args.out.exists() else [])
    for name in scenarios:
        resume = next((e for e in results
                       if e.get("scenario") == name), None)
        entry = run_scenario(name, args.runs, None, args.work,
                             resume=resume)
        if resume is not None:
            results[results.index(resume)] = entry
        else:
            results.append(entry)
        checkpoint(args.out, results)
        print(_entry_line(entry))
    text = report(results)
    checkpoint(args.out, results, summary=text)
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
