"""Eval harness tests: every live boundary stubbed, offline (ADR-0002:
run_eval.py is never executed here — each live run costs the lab plus
Groq calls; these tests import the harness and stub the capture, the
detect-kpi boundary, the analyze step, the pipeline and the judge).

The harness is the only runner that ever touches Groq: pytest never
builds the judge's LM — the laziness test reaches the live default
through the real function and only asserts the key-guard raise."""

import pytest

import dispatch.executor as executor_mod
from evals.run_eval import (SCENARIOS, JUDGE, brief, checkpoint,
                            load_results, report, run_scenario)
from evals.run_eval import default_judge as live_default_judge

CAPTURES = {
    "n2": "/tmp/n4_upf_timeout.pcap",
    "sbi": "/tmp/n4_upf_timeout_sbi.pcap",
    "n4": "/tmp/n4_upf_timeout_n4.pcap",
    "label": {"incident_type": "n4_upf_timeout",
              "scenario": "n4_upf_timeout"},
}

EVENT = {
    "incident_id": "inc-kpi-12345678",
    "description": "KPI degradation: procedure_success_rate=0.80",
    "source": "kpi",
    "procedure": None,
    "time_window": {"start": 1750000000.0, "end": 1750000060.0},
    "kpi": {"procedure_success_rate": 0.8},
    "captures": CAPTURES,
}

# A merged export with one failure shape per plane, for the brief.
MERGED_EXPORT = {
    "kpis": {"procedure_success_rate": 0.8,
             "procedure_successes": 4, "procedure_failures": 1},
    "flows": [{
        "flow_id": 1, "partial": False,
        "messages": [{"ts": 1750000000.0, "ngap": "DownlinkNASTransport",
                      "nas": "5GMMStatus",
                      "nas_cause": {"code": 91,
                                    "name": "Payload was not forwarded"}}],
        "procedures": []}],
    "n4": {"messages": [], "procedures": [
        {"kind": "session_establishment", "outcome": "timeout"}],
        "unpaired_requests": 1},
    "sbi": {"messages": [], "procedures": [
        {"kind": "Nnssf_NSSelection", "outcome": "reject", "status": 403}],
        "unpaired_requests": 0},
}

RECORD = ("# Incident Record inc-kpi-12345678\n\n## Root cause\n\n"
          "The UPF logged the request and never answered it.\n")

SCORES = {"accuracy": 1.0, "specificity": 0.9, "evidence": 0.8,
          "causality": 0.7, "proposal": 0.6}


def stub_capture(name):
    return CAPTURES


def stub_detect(captures):
    return EVENT


def stub_analyze(captures):
    return MERGED_EXPORT


def stub_pipeline(event, run_dir):
    (run_dir / "records").mkdir(parents=True)
    (run_dir / "records" / f'{event["incident_id"]}.md').write_text(RECORD)
    return RECORD


def make_judge(calls):
    def judge(record, facts):
        calls.append((record, facts))
        return {"scores": dict(SCORES), "comment": "grounded"}
    return judge


def test_scenarios_are_the_executor_vocabulary():
    # The harness runs the executor's ten failure-injection scenarios —
    # one list, so the harness can never drift from the sandbox.
    assert SCENARIOS == executor_mod.SCENARIOS
    assert len(SCENARIOS) == 10


def test_judge_model_is_distinct_from_the_generator():
    # AC: the judge model is distinct from the generator (gpt-oss-120b).
    # Same doubled vendor prefix trick as triage's harness, same base.
    assert "gpt-oss" not in JUDGE[0]
    assert "qwen" in JUDGE[0]
    assert JUDGE[1] == "https://api.groq.com/openai/v1"


def test_brief_carries_merged_facts():
    # The judge grounds in decoded captures only: the brief carries the
    # merged export's failure shapes per plane, never the label.
    text = brief(MERGED_EXPORT)
    assert "procedure_success_rate=0.8" in text
    assert "5GMMStatus" in text
    assert "nas_cause 91" in text
    assert "session_establishment" in text
    assert "timeout" in text
    assert "Nnssf_NSSelection" in text
    assert "403" in text


def test_default_judge_builds_lazily_and_requires_groq_key(monkeypatch):
    # ADR-0002: construction is key-free; a call without GROQ_API_KEY
    # raises before any dspy.LM construction, never touching the network.
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    judge = live_default_judge()
    assert callable(judge)
    with pytest.raises(RuntimeError, match="GROQ_API_KEY"):
        judge(RECORD, brief(MERGED_EXPORT))


def test_run_scenario_scores_each_run(tmp_path):
    # The real shape of a judged run: capture once, detect the event,
    # decode once for the brief, then per run a fresh pipeline pass and
    # a judge call over (record, brief).
    judge_calls = []
    entry = run_scenario("n4_upf_timeout", 2, make_judge(judge_calls),
                         tmp_path, capture=stub_capture,
                         detect=stub_detect, analyze=stub_analyze,
                         pipeline=stub_pipeline)
    assert entry["event"]["incident_id"] == EVENT["incident_id"]
    assert entry["label"] == CAPTURES["label"]
    assert entry["facts"] == brief(MERGED_EXPORT)
    assert [r["run"] for r in entry["runs"]] == [0, 1]
    assert entry["runs"][0]["scores"] == SCORES
    assert entry["runs"][0]["quality"] == pytest.approx(0.8)
    assert all(r["record"] == RECORD for r in entry["runs"])
    assert all(r["comment"] == "grounded" for r in entry["runs"])
    # every judge call saw the record text and the decoded facts
    assert [c[0] for c in judge_calls] == [RECORD, RECORD]
    assert all(c[1] == brief(MERGED_EXPORT) for c in judge_calls)


def test_run_scenario_captures_and_decodes_once_across_runs(tmp_path):
    seen = {"capture": 0, "detect": 0, "analyze": 0, "pipeline": []}

    def capture(name):
        seen["capture"] += 1
        return CAPTURES

    def detect(captures):
        seen["detect"] += 1
        return EVENT

    def analyze(captures):
        seen["analyze"] += 1
        return MERGED_EXPORT

    def pipeline(event, run_dir):
        seen["pipeline"].append(run_dir)
        return RECORD

    run_scenario("n4_upf_timeout", 2, make_judge([]), tmp_path,
                 capture=capture, detect=detect, analyze=analyze,
                 pipeline=pipeline)
    # the capture is the expensive live step: once per scenario, then
    # the same captures feed every run (fresh per-run dirs make the
    # identical incident id re-runnable)
    assert (seen["capture"], seen["detect"], seen["analyze"]) == (1, 1, 1)
    assert len(seen["pipeline"]) == 2
    assert seen["pipeline"][0] != seen["pipeline"][1]
    assert all("n4_upf_timeout" in str(p) for p in seen["pipeline"])


def test_run_scenario_miss_reports_no_event(tmp_path):
    # The real detect-kpi boundary: healthy KPIs produce no event, and
    # the harness reports the miss instead of fabricating one.
    entry = run_scenario("n4_upf_timeout", 2, make_judge([]), tmp_path,
                         capture=stub_capture, detect=lambda c: None,
                         analyze=lambda c: pytest.fail("never runs"),
                         pipeline=lambda e, d: pytest.fail("never runs"))
    assert entry["event"] is None
    assert entry["runs"] == []
    assert entry["label"] == CAPTURES["label"]


def test_run_scenario_resume_skips_done_runs(tmp_path):
    # Checkpoint/resume bookkeeping: a resumed entry reuses its event,
    # facts and label (no capture/detect/analyze), and a fully completed
    # entry resumes to nothing new.
    seen = {"capture": 0, "pipeline": []}

    def capture(name):
        seen["capture"] += 1
        return CAPTURES

    def pipeline(event, run_dir):
        seen["pipeline"].append(run_dir)
        return RECORD

    entry = run_scenario("n4_upf_timeout", 2, make_judge([]), tmp_path,
                         capture=capture, detect=stub_detect,
                         analyze=stub_analyze, pipeline=pipeline)
    resumed = run_scenario("n4_upf_timeout", 2, make_judge([]), tmp_path,
                           resume=entry, capture=capture,
                           detect=stub_detect, analyze=stub_analyze,
                           pipeline=pipeline)
    assert resumed["event"]["incident_id"] == EVENT["incident_id"]
    assert resumed["facts"] == brief(MERGED_EXPORT)
    assert seen["capture"] == 1      # the live lab was touched once
    assert len(seen["pipeline"]) == 2  # both runs already done


def test_run_scenario_resume_runs_only_missing_runs(tmp_path):
    seen = {"pipeline": []}

    def pipeline(event, run_dir):
        seen["pipeline"].append(run_dir)
        return RECORD

    entry = run_scenario("n4_upf_timeout", 2, make_judge([]), tmp_path,
                         capture=stub_capture, detect=stub_detect,
                         analyze=stub_analyze, pipeline=pipeline)
    del entry["runs"][1]             # interrupted after the first run
    resumed = run_scenario("n4_upf_timeout", 2, make_judge([]), tmp_path,
                           resume=entry, capture=stub_capture,
                           detect=stub_detect, analyze=stub_analyze,
                           pipeline=pipeline)
    assert [r["run"] for r in resumed["runs"]] == [0, 1]
    assert len(seen["pipeline"]) == 3  # only the missing run re-ran


def test_run_scenario_resume_retries_errored_runs(tmp_path):
    # A run whose previous attempt errored re-runs on resume and the
    # stale error entry is dropped — the checkpoint never accumulates
    # two entries for one run number.
    seen = {"pipeline": []}

    def pipeline(event, run_dir):
        seen["pipeline"].append(run_dir)
        return RECORD

    entry = run_scenario("n4_upf_timeout", 2, make_judge([]), tmp_path,
                         capture=stub_capture, detect=stub_detect,
                         analyze=stub_analyze, pipeline=pipeline)
    entry["runs"][1] = {"run": 1, "error": "pipeline exploded"}  # stale
    resumed = run_scenario("n4_upf_timeout", 2, make_judge([]), tmp_path,
                           resume=entry, capture=stub_capture,
                           detect=stub_detect, analyze=stub_analyze,
                           pipeline=pipeline)
    assert [r["run"] for r in resumed["runs"]] == [0, 1]
    assert all("scores" in r and "error" not in r
               for r in resumed["runs"])
    assert len(seen["pipeline"]) == 3   # run 1 re-ran, run 0 skipped


def test_run_scenario_capture_failure_records_error(tmp_path):
    # A down lab degrades per scenario, never kills the harness.
    def capture(name):
        raise RuntimeError("lab down")

    entry = run_scenario("n4_upf_timeout", 2, make_judge([]), tmp_path,
                         capture=capture)
    assert entry["error"] == "lab down"
    assert entry["event"] is None
    assert entry["runs"] == []


def test_capture_scenario_merged_name_reads_the_n2_triple(tmp_path,
                                                          monkeypatch):
    # capture.sh's merged-eval exception writes the N2 dump under the
    # golden-style _n2 name — no unsuffixed pcap exists for the harness
    # to read.
    import evals.run_eval as eval_mod

    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "pdu_session_rsp_timeout.label.json").write_text(
        '{"incident_type": "pdu_session_rsp_timeout", '
        '"scenario": "pdu_session_rsp_timeout"}')
    for suffix in ("_n2.pcap", "_sbi.pcap", "_n4.pcap"):
        (fixtures / f"pdu_session_rsp_timeout{suffix}").write_bytes(b"")
    ok = type("Result", (), {"returncode": 0, "stderr": "", "stdout": ""})()
    monkeypatch.setattr(eval_mod, "FIXTURES", fixtures)
    monkeypatch.setattr(eval_mod.subprocess, "run", lambda *a, **k: ok)

    captures = eval_mod.capture_scenario("pdu_session_rsp_timeout")
    assert captures["n2"].endswith("pdu_session_rsp_timeout_n2.pcap")
    assert captures["label"]["incident_type"] == "pdu_session_rsp_timeout"


def test_run_scenario_pipeline_failure_records_run_error(tmp_path):
    # A failed pipeline pass is an entry error on that run; the other
    # runs and scenarios keep going.
    calls = []

    def pipeline(event, run_dir):
        calls.append(run_dir)
        if len(calls) == 1:
            raise RuntimeError("pipeline exploded")
        return RECORD

    entry = run_scenario("n4_upf_timeout", 2, make_judge([]), tmp_path,
                         capture=stub_capture, detect=stub_detect,
                         analyze=stub_analyze, pipeline=pipeline)
    assert entry["runs"][0]["error"] == "pipeline exploded"
    assert "scores" not in entry["runs"][0]
    assert entry["runs"][1]["scores"] == SCORES


def test_report_lists_scenario_means_dims_and_misses():
    # Per-scenario results with the ground-truth label as a reference
    # column (never judge input), dim means, misses and errors.
    judged = {
        "scenario": "n4_upf_timeout",
        "label": CAPTURES["label"], "event": EVENT, "facts": "facts",
        "runs": [{"run": 0, "scores": {"accuracy": 1.0, "specificity": 0.9,
                                      "evidence": 0.8, "causality": 0.7,
                                      "proposal": 0.6}, "comment": "ok",
                  "record": "x", "quality": 0.8},
                 {"run": 1, "scores": {"accuracy": 0.8, "specificity": 0.7,
                                      "evidence": 0.6, "causality": 0.5,
                                      "proposal": 0.4}, "comment": "ok",
                  "record": "x", "quality": 0.6}]}
    missed = {"scenario": "auth_failure", "label": CAPTURES["label"],
              "event": None, "runs": []}
    failed = {"scenario": "registration_reject",
              "label": None, "event": None, "error": "lab down",
              "runs": []}
    text = report([judged, missed, failed])
    assert "n4_upf_timeout" in text
    assert "(label: n4_upf_timeout)" in text
    assert "quality 0.70 over 2 runs" in text
    assert "accuracy" in text and "proposal" in text
    assert "auth_failure" in text
    assert "no event detected" in text
    assert "registration_reject" in text
    assert "lab down" in text
    assert "1 missed" in text
    assert "1 error" in text


def test_checkpoint_roundtrip(tmp_path):
    # {"summary": None, "runs": results} — the resume contract.
    results = [{"scenario": "auth_failure", "label": None, "event": None,
                "runs": []}]
    out = tmp_path / "results.json"
    checkpoint(out, results)
    assert load_results(out) == {"summary": None, "runs": results}
    assert load_results(tmp_path / "missing.json") == \
        {"summary": None, "runs": []}
