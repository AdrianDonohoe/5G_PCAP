"""The offline eval harness: type_accuracy + diagnosis_quality over the six
labeled failure-injection fixtures.

ADR-0002: lives in evals/, run explicitly (`uv run python evals/run_eval.py`
from triage/) — every fixture run costs real Groq calls, so this never runs
inside the pytest suite. Targets: type_accuracy >= 5/6 (mean over fixtures)
and diagnosis_quality mean >= 0.7 (mean over runs; a run whose search
completes no Hypothesis scores 0.0).

Pipeline per fixture run: decode once with 5gcap's CLI (subprocess; shared
across the three runs), auto-detect the failed Incidents, run one LATS
search per Incident (gpt-oss:120b via Groq), then score each Hypothesis on
four 0-1 dimensions with an LLM judge that is a distinct model from the
generator. The judge is qwen3.6-27b on the same Groq account: the task's
judge (llama-3.3-70b-versatile) is not served there, and a different model
family entirely is what "distinct" exists for. Episodic memory is reset
before each fixture run (a fresh temp store), so consolidation never
dedups across runs.

GROQ_API_KEY must be set. The `spec` Action's embedding index builds on
first use and caches in triage/corpus/cache/ afterwards.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import dspy

from triage.evidence import load_capture
from triage.incidents import detect_incidents
from triage.memory import MemoryStore
from triage.search import run_lats

FIXTURES = ["auth_failure", "registration_reject", "registration_timeout",
            "pdu_session_reject_slice", "pdu_session_reject_other",
            "pdu_session_timeout"]

ROOT = Path(__file__).resolve().parent.parent      # triage/
FIVEGCAP = ROOT.parent / "5gcap"
FIXTURE_DIR = FIVEGCAP / "tests" / "fixtures"

# Same Groq vendor-prefix gotcha as triage.search.GROQ: dspy strips the
# first segment as provider, so the doubled "openai/" keeps Groq's
# "qwen/qwen3.6-27b" model ID intact.
JUDGE = ("openai/qwen/qwen3.6-27b", "https://api.groq.com/openai/v1")


# --- the diagnosis_quality judge ---

class JudgeSignature(dspy.Signature):
    """You are an independent evaluator scoring a root-cause hypothesis for
    a failed 5G Registration / PDU Session procedure. Check every claim in
    the hypothesis against the decoded messages and score each dimension
    0.0 (fails) to 1.0 (excellent):

    - accuracy: the factual claims match the decoded messages — no invented
      messages, cause codes, or network elements
    - specificity: names concrete messages, causes, and elements rather
      than vague phrasing ("network issue", "a failure")
    - evidence: the cited evidence appears in the decoded messages and
      supports the hypothesis's claim
    - causality: explains the mechanism behind the failure (why this
      message sequence happened), not just that a reject occurred

    For a timeout-shaped failure the decode may hold only the initiating
    request(s): the missing terminal message IS the mechanism. Score the
    hypothesis on stating what arrived and that nothing answered, and do
    not penalize it for not naming which network element failed when the
    decode carries no evidence to distinguish them."""
    hypothesis: str = dspy.InputField(desc="The hypothesis being scored")
    decoded: str = dspy.InputField(
        desc="The decoded messages to check claims against")
    accuracy: float = dspy.OutputField(desc="0.0 to 1.0")
    specificity: float = dspy.OutputField(desc="0.0 to 1.0")
    evidence: float = dspy.OutputField(desc="0.0 to 1.0")
    causality: float = dspy.OutputField(desc="0.0 to 1.0")
    comment: str = dspy.OutputField(desc="One sentence: the main weakness")


DIMS = ("accuracy", "specificity", "evidence", "causality")


def default_judge():
    """judge(hypothesis, decoded) -> {"scores": {...}, "comment": ...}.

    The judge LM must be re-configured before every call: run_lats
    reconfigures dspy to the generator model each time it builds its
    predictors, and dspy resolves the configured LM at call time. A judge
    call that fails (e.g. Groq rejecting malformed JSON) retries once, then
    scores 0.0 with an error comment — a judge failure must never kill the
    harness."""
    predictor = dspy.Predict(JudgeSignature)

    def judge(hypothesis: str, decoded: str) -> dict:
        key = os.environ.get("GROQ_API_KEY")
        if not key:
            raise RuntimeError("GROQ_API_KEY is not set (ADR-0002: no local "
                               "model fallback)")
        lm = dspy.LM(JUDGE[0], api_base=JUDGE[1], api_key=key, cache=False,
                     max_tokens=4096)
        dspy.configure(lm=lm)
        for attempt in range(2):
            try:
                result = predictor(hypothesis=hypothesis, decoded=decoded)
                break
            except Exception as exc:
                if attempt == 1:
                    return {"scores": {dim: 0.0 for dim in DIMS},
                            "comment": f"judge failed: {exc}"}
        scores = {}
        for dim in DIMS:
            try:
                scores[dim] = min(1.0, max(0.0,
                                           float(getattr(result, dim))))
            except (TypeError, ValueError):
                scores[dim] = 0.0  # judge failed to score: the dim scores 0
        return {"scores": scores,
                "comment": str(getattr(result, "comment", ""))}
    return judge


# --- fixture I/O and briefs ---

def decode_fixture(name: str, workdir: Path) -> Path:
    """Decode one fixture pcap with 5gcap's CLI (the JSON contract, not
    fivegcap's Python API)."""
    pcap = FIXTURE_DIR / f"{name}.pcap"
    target = workdir / f"{name}_n2.json"
    subprocess.run(["uv", "run", "5gcap", "analyze", str(pcap), "--json",
                    str(target)], cwd=FIVEGCAP, check=True,
                   capture_output=True, text=True)
    return target


def label_for(name: str) -> str:
    return json.loads((FIXTURE_DIR / f"{name}.label.json")
                      .read_text(encoding="utf-8"))["incident_type"]


def _flow_brief(capture, flow_id) -> str:
    """The Incident's decoded messages, for the judge to check claims
    against — including the flow's time span and the absence of a terminal
    procedure, so a timeout failure is visible as evidence."""
    flow = next(f for f in capture.n2.get("flows") or []
                if f.get("flow_id") == flow_id)
    msgs = flow.get("messages") or []
    lines = []
    if msgs:
        lines.append(f"flow span: {msgs[0]['ts']:.3f}s -> "
                     f"{msgs[-1]['ts']:.3f}s ({len(msgs)} message(s))")
    if not flow.get("procedures"):
        lines.append("no procedure records: no terminal message ever arrived")
    for msg in msgs:
        name = (msg.get("nas_inner") or msg.get("nas") or msg.get("ngap")
                or "?")
        cause = msg.get("nas_cause") or {}
        lines.append(f"{msg['ts']:.3f} {name}"
                     + (f" cause #{cause['code']} ({cause['name']})"
                        if cause.get("code") else ""))
    for proc in flow.get("procedures") or []:
        lines.append(f"procedure {proc.get('kind')}: {proc.get('outcome')}")
    return "\n".join(lines)


def _hypothesis_brief(incident: dict, episode) -> str:
    cited = "; ".join(
        ev.message
        + (f" cause #{ev.cause}" if ev.cause is not None else "")
        + (f" @{ev.ts:.3f}s" if ev.ts is not None else "")
        for ev in episode.cited_evidence)
    return (f"Procedure: {incident['procedure']} ({incident['shape']}), "
            f"flow {incident['flow_id']}\n"
            f"incident_type: {episode.incident_type}\n"
            f"narrative: {episode.narrative}\n"
            f"cited evidence: {cited}")


# --- one fixture x one run ---

def run_fixture(name: str, n2_path: Path, label: str, runs: int,
                judge, done: set | None = None) -> list[dict]:
    done = done or set()
    capture = load_capture(str(n2_path))
    incidents = detect_incidents(capture.n2)
    if not incidents:
        print(f"{name}: no Incidents detected in the decode — "
              f"0.0 for every run", flush=True)
        return [{"fixture": name, "run": i, "label": label,
                 "incident_types": [], "type_accuracy": 0.0,
                 "hypotheses": [], "rollouts": []}
                for i in range(1, runs + 1) if (name, i) not in done]
    results = []
    for run_i in range(1, runs + 1):
        if (name, run_i) in done:
            print(f"{name} run {run_i}: skipped (in checkpoint)", flush=True)
            continue
        store = MemoryStore(Path(tempfile.gettempdir()) /
                            f"triage_eval_{name}_{run_i}.jsonl")
        hypotheses = []  # (incident, SearchResult) pairs with an Episode
        for incident in incidents:
            result = run_lats(capture, incident, store=store)
            if result.episode is not None:
                hypotheses.append((incident, result))
        types = [res.episode.incident_type for _, res in hypotheses]
        scored = []
        for incident, res in hypotheses:
            verdict = judge(_hypothesis_brief(incident, res.episode),
                            _flow_brief(capture, incident["flow_id"]))
            verdict.update(flow_id=incident["flow_id"],
                           incident_type=res.episode.incident_type,
                           narrative=res.episode.narrative,
                           rollouts=res.rollouts, reward=res.reward)
            scored.append(verdict)
        entry = {"fixture": name, "run": run_i, "label": label,
                 "incident_types": types,
                 "type_accuracy": 1.0 if label in types else 0.0,
                 "hypotheses": scored,
                 "rollouts": [res.rollouts for _, res in hypotheses]}
        results.append(entry)
        diag = _run_diag(entry)
        print(f"{name} run {run_i}: incident_types={types} "
              f"type_accuracy={entry['type_accuracy']:.1f} "
              f"diagnosis_quality={diag:.2f}", flush=True)
    return results


def _run_diag(entry: dict) -> float:
    """A run with no completed Hypothesis scores 0.0."""
    if not entry["hypotheses"]:
        return 0.0
    return sum(sum(h["scores"].values()) / 4
               for h in entry["hypotheses"]) / len(entry["hypotheses"])


# --- report ---

def report(results: list[dict]) -> dict:
    """Fixture-level type_accuracy, run-level diagnosis_quality, and
    per-dimension means."""
    by_fixture = {}
    for entry in results:
        by_fixture.setdefault(entry["fixture"], []).append(entry)
    fixture_ta = {name: sum(e["type_accuracy"] for e in entries)
                  / len(entries) for name, entries in by_fixture.items()}
    diag_by_fixture = {name: sum(_run_diag(e) for e in entries)
                       / len(entries) for name, entries in by_fixture.items()}
    dims = {dim: [] for dim in ("accuracy", "specificity", "evidence",
                                "causality")}
    for entry in results:
        for h in entry["hypotheses"]:
            for dim in dims:
                dims[dim].append(h["scores"][dim])
    summary = {
        "fixture_type_accuracy": fixture_ta,
        "type_accuracy": sum(fixture_ta.values()) / len(fixture_ta),
        "diagnosis_quality_by_fixture": diag_by_fixture,
        "diagnosis_quality": sum(diag_by_fixture.values())
        / len(diag_by_fixture),
        "dimension_means": {dim: (sum(v) / len(v) if v else 0.0)
                            for dim, v in dims.items()},
        "judged_hypotheses": sum(len(e["hypotheses"]) for e in results),
        "completed_runs": sum(bool(e["hypotheses"]) for e in results),
        "runs": len(results),
    }
    lines = [
        f"\n=== triage eval ({summary['runs']} fixture-runs) ===",
        f"type_accuracy:       {summary['type_accuracy']:.3f} "
        f"(target >= {5 / 6:.3f})",
        f"diagnosis_quality:   {summary['diagnosis_quality']:.3f} "
        f"(target >= 0.700)",
        f"completed runs:      {summary['completed_runs']}/"
        f"{summary['runs']} "
        f"({summary['judged_hypotheses']} hypothesis(es) judged)",
        "dimension means:      " + ", ".join(
            f"{dim}={v:.2f}" for dim, v in summary["dimension_means"].items()),
        "per fixture:",
    ]
    for name in FIXTURES:
        if name in fixture_ta:
            lines.append(f"  {name:24s} type_accuracy={fixture_ta[name]:.3f} "
                         f" diagnosis_quality={diag_by_fixture[name]:.3f}")
    return summary, "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="evals/run_eval.py",
        description="type_accuracy + diagnosis_quality over the labeled "
                    "sandbox fixtures (real Groq calls).")
    parser.add_argument("--fixtures", default=",".join(FIXTURES),
                        help="comma-separated fixture subset "
                             f"(default: all {len(FIXTURES)})")
    parser.add_argument("--runs", type=int, default=3,
                        help="searches per fixture (default: 3)")
    parser.add_argument("--out", default=str(ROOT / "evals" / "results.json"),
                        help="JSON results path")
    parser.add_argument("--resume", action="store_true",
                        help="skip fixture-runs already present in --out")
    args = parser.parse_args(argv)
    names = [n.strip() for n in args.fixtures.split(",") if n.strip()]
    unknown = [n for n in names if n not in FIXTURES]
    if unknown:
        print(f"evals: error: unknown fixture(s): {', '.join(unknown)}",
              file=sys.stderr)
        return 1
    judge = default_judge()

    def checkpoint() -> None:
        # write what has been computed so far: a crash mid-run must not
        # lose every already-paid-for result
        Path(args.out).write_text(
            json.dumps({"summary": None, "runs": results}, indent=2) + "\n",
            encoding="utf-8")

    results = []
    if args.resume:
        try:
            results = json.loads(Path(args.out).read_text(encoding="utf-8"))[
                "runs"]
        except (OSError, json.JSONDecodeError, KeyError):
            print(f"evals: error: cannot resume from {args.out} — not a "
                  f"checkpoint", file=sys.stderr)
            return 1
        print(f"resume: {len(results)} run(s) loaded from {args.out}",
              flush=True)
    done = {(entry["fixture"], entry["run"])
            for entry in results if entry.get("run")}
    with tempfile.TemporaryDirectory() as workdir:
        for name in names:
            if all((name, run) in done for run in range(1, args.runs + 1)):
                print(f"=== {name}: all {args.runs} run(s) in checkpoint — "
                      f"skipping ===", flush=True)
                continue
            print(f"=== {name} (label {label_for(name)}) ===", flush=True)
            try:
                n2_path = decode_fixture(name, Path(workdir))
            except subprocess.CalledProcessError as exc:
                print(f"evals: error: decoding {name} failed:\n{exc.stderr}",
                      file=sys.stderr)
                return 1
            try:
                results.extend(run_fixture(name, n2_path, label_for(name),
                                           args.runs, judge, done))
            except Exception as exc:  # record the failure, keep the run alive
                print(f"{name}: FAILED: {exc} — recording and continuing",
                      file=sys.stderr, flush=True)
                results.append({"fixture": name, "error": str(exc),
                                "incident_types": [],
                                "type_accuracy": 0.0, "hypotheses": [],
                                "rollouts": []})
            checkpoint()
    summary, text = report(results)
    print(text)
    Path(args.out).write_text(
        json.dumps({"summary": summary, "runs": results}, indent=2) + "\n",
        encoding="utf-8")
    print(f"results written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
