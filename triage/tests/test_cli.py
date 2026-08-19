"""triage analyze and triage report end-to-end via cli.main with stubbed
search/memory/loading (ADR-0002: the suite never calls Groq or builds the
spec graph)."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from triage.cli import main
from triage.memory import Episode

EPISODE = Episode(
    incident_type="registration_reject",
    narrative="UDM says no: IMSI unknown.",
    cited_evidence=[{"message": "5GMMRegistrationReject", "cause": 111,
                     "ts": 2.0}])


def reject_flow(fid):
    return {"flow_id": fid, "messages": [
        {"ts": 1.0, "nas": "5GMMRegistrationRequest"},
        {"ts": 2.0, "nas_inner": "5GMMRegistrationReject",
         "nas_cause": {"code": 111}}],
        "procedures": [{"kind": "registration", "outcome": "reject",
                        "start_msg": "5GMMRegistrationRequest",
                        "end_msg": "5GMMRegistrationReject"}],
        "partial": False}


@pytest.fixture
def fake_search(monkeypatch):
    """run_lats -> a completed SearchResult; records (flow_id, store)."""
    calls = []

    def run(capture, incident, store=None, **kwargs):
        calls.append((incident["flow_id"], store))
        return SimpleNamespace(
            episode=EPISODE, reward=0.9, rollouts=2,
            trajectory=[("inspect flows", "Flow 1 (2 message(s))")])

    monkeypatch.setattr("triage.cli.run_lats", run)
    return calls


@pytest.fixture
def fake_consolidate(monkeypatch):
    wrote = []

    def cons(episode, store):
        wrote.append(episode)
        return episode, True

    monkeypatch.setattr("triage.cli.consolidate", cons)
    return wrote


def captured(capsys):
    """One read of the captured output: (parsed stdout JSON, stderr text)."""
    res = capsys.readouterr()
    return json.loads(res.out), res.err


def test_analyze_success(fake_search, fake_consolidate, monkeypatch, capsys):
    monkeypatch.setattr("triage.cli.load_capture",
                        lambda n2, n4=None, sbi=None: SimpleNamespace(n4=None, 
                            n2={"flows": [reject_flow(1)]}, sbi=sbi))
    assert main(["analyze", "capture_n2.json"]) == 0
    results, err = captured(capsys)
    assert len(results) == 1
    result = results[0]
    assert result["plane"] == "n2"
    assert result["flow_id"] == 1
    assert result["procedure"] == "Registration"
    assert result["shape"] == "explicit reject"
    assert result["episode"]["incident_type"] == "registration_reject"
    assert result["reward"] == 0.9 and result["rollouts"] == 2
    assert result["memory_wrote"] is True
    assert "memory: new Episode written" in err
    assert "hypothesis: registration_reject" in err


def test_zero_incidents_is_success(monkeypatch, capsys):
    monkeypatch.setattr("triage.cli.load_capture",
                        lambda n2, n4=None, sbi=None: SimpleNamespace(n4=None, 
                            n2={"flows": [{"flow_id": 1, "messages": [],
                                           "procedures": [], "partial": False}]},
                            sbi=sbi))
    assert main(["analyze", "golden.json"]) == 0
    results, err = captured(capsys)
    assert results == []
    assert "no failed Incidents detected" in err


def test_flow_filter_runs_only_matching_incident(fake_search,
                                                 fake_consolidate,
                                                 monkeypatch, capsys):
    monkeypatch.setattr("triage.cli.load_capture",
                        lambda n2, n4=None, sbi=None: SimpleNamespace(n4=None, 
                            n2={"flows": [reject_flow(1), reject_flow(2)]},
                            sbi=sbi))
    assert main(["analyze", "x.json", "--flow", "2"]) == 0
    assert [flow_id for flow_id, _ in fake_search] == [2]
    results, _ = captured(capsys)
    assert [r["flow_id"] for r in results] == [2]


def test_flow_filter_matching_none(monkeypatch, capsys):
    monkeypatch.setattr("triage.cli.load_capture",
                        lambda n2, n4=None, sbi=None: SimpleNamespace(n4=None, 
                            n2={"flows": [reject_flow(1)]}, sbi=sbi))
    assert main(["analyze", "x.json", "--flow", "9"]) == 0
    results, err = captured(capsys)
    assert results == []
    assert "--flow 9 matched none" in err


def sbi_reject_procedure():
    return {"kind": "Nnssf_NSSelection", "outcome": "reject", "status": 403}


def test_analyze_sbi_incidents(fake_search, fake_consolidate, monkeypatch,
                               capsys, tmp_path):
    sbi = tmp_path / "capture_sbi.json"
    sbi.write_text(json.dumps({"messages": [], "procedures": [
        sbi_reject_procedure()]}) + "\n")
    monkeypatch.setattr("triage.cli.load_capture",
                        lambda n2, n4=None, sbi=None: SimpleNamespace(
                            n2={"flows": []}, n4=None,
                            sbi=json.loads(Path(sbi).read_text())
                            if sbi else None))
    assert main(["analyze", "capture_n2.json", "--sbi", str(sbi)]) == 0
    assert [flow_id for flow_id, _ in fake_search] == [None]
    results, err = captured(capsys)
    assert len(results) == 1
    result = results[0]
    assert result["plane"] == "sbi"
    assert result["flow_id"] is None
    assert result["procedure"] == "Nnssf_NSSelection"
    assert result["shape"] == "explicit reject"
    assert result["detail"] == "SBI status code(s) observed: 403"
    assert "SBI Nnssf_NSSelection Nnssf_NSSelection (explicit reject)" in err


def test_analyze_without_sbi_flag_detects_n2_only(fake_search,
                                                  fake_consolidate,
                                                  monkeypatch, capsys):
    monkeypatch.setattr("triage.cli.load_capture",
                        lambda n2, n4=None, sbi=None: SimpleNamespace(
                            n2={"flows": [reject_flow(1)]}, n4=None, sbi=None))
    assert main(["analyze", "capture_n2.json"]) == 0
    assert [flow_id for flow_id, _ in fake_search] == [1]
    results, _ = captured(capsys)
    assert [r["plane"] for r in results] == ["n2"]


def test_flow_filter_drops_sbi_incidents(fake_search, fake_consolidate,
                                         monkeypatch, capsys, tmp_path):
    sbi = tmp_path / "capture_sbi.json"
    sbi.write_text(json.dumps({"messages": [], "procedures": [
        sbi_reject_procedure()]}) + "\n")
    monkeypatch.setattr("triage.cli.load_capture",
                        lambda n2, n4=None, sbi=None: SimpleNamespace(
                            n2={"flows": [reject_flow(1)]}, n4=None,
                            sbi=json.loads(Path(sbi).read_text())
                            if sbi else None))
    assert main(["analyze", "capture_n2.json", "--sbi", str(sbi),
                 "--flow", "1"]) == 0
    assert [flow_id for flow_id, _ in fake_search] == [1]


def test_load_error_exits_1(monkeypatch, capsys):
    def boom(n2, n4=None, sbi=None):
        raise ValueError("boom")
    monkeypatch.setattr("triage.cli.load_capture", boom)
    assert main(["analyze", "bad.json"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "triage: error: cannot load bad.json: boom" in captured.err


def test_groq_key_error_exits_1(fake_consolidate, monkeypatch, capsys):
    monkeypatch.setattr("triage.cli.load_capture",
                        lambda n2, n4=None, sbi=None: SimpleNamespace(n4=None, 
                            n2={"flows": [reject_flow(1)]}, sbi=sbi))

    def no_key(capture, incident, store=None, **kwargs):
        raise RuntimeError("GROQ_API_KEY is not set (ADR-0002: no local "
                           "model fallback)")
    monkeypatch.setattr("triage.cli.run_lats", no_key)
    assert main(["analyze", "x.json"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "triage: error: GROQ_API_KEY is not set" in captured.err


def test_no_hypothesis_reports_null_episode(fake_consolidate, monkeypatch,
                                            capsys):
    monkeypatch.setattr("triage.cli.load_capture",
                        lambda n2, n4=None, sbi=None: SimpleNamespace(n4=None, 
                            n2={"flows": [reject_flow(1)]}, sbi=sbi))
    monkeypatch.setattr("triage.cli.run_lats",
                        lambda capture, incident, store=None, **kwargs:
                        SimpleNamespace(episode=None, reward=0.0, rollouts=10,
                                        trajectory=[]))
    assert main(["analyze", "x.json"]) == 0
    results, err = captured(capsys)
    result = results[0]
    assert result["episode"] is None
    assert result["memory_wrote"] is False
    assert "no hypothesis" in err
    assert fake_consolidate == []


def test_duplicate_episode_not_written(monkeypatch, capsys):
    monkeypatch.setattr("triage.cli.load_capture",
                        lambda n2, n4=None, sbi=None: SimpleNamespace(n4=None, 
                            n2={"flows": [reject_flow(1)]}, sbi=sbi))
    monkeypatch.setattr("triage.cli.run_lats",
                        lambda capture, incident, store=None, **kwargs:
                        SimpleNamespace(episode=EPISODE, reward=0.9,
                                        rollouts=2, trajectory=[]))
    monkeypatch.setattr("triage.cli.consolidate",
                        lambda episode, store: (EPISODE, False))
    assert main(["analyze", "x.json"]) == 0
    results, err = captured(capsys)
    assert results[0]["memory_wrote"] is False
    assert "duplicate of an existing Episode, not written" in err


def test_episodes_path_override(monkeypatch, tmp_path, capsys):
    seen = []

    class RecordingStore:
        def __init__(self, path=None):
            seen.append(path)
            self.backing = {}
    monkeypatch.setattr("triage.cli.load_capture",
                        lambda n2, n4=None, sbi=None: SimpleNamespace(n4=None, 
                            n2={"flows": [reject_flow(1)]}, sbi=sbi))
    monkeypatch.setattr("triage.cli.run_lats",
                        lambda capture, incident, store=None, **kwargs:
                        SimpleNamespace(episode=EPISODE, reward=0.9,
                                        rollouts=2, trajectory=[]))
    monkeypatch.setattr("triage.cli.consolidate",
                        lambda episode, store: (EPISODE, True))
    monkeypatch.setattr("triage.cli.MemoryStore", RecordingStore)
    from pathlib import Path
    assert main(["analyze", "x.json",
                 "--episodes-path", str(tmp_path / "mem.jsonl")]) == 0
    assert seen == [Path(tmp_path / "mem.jsonl")]


def test_verbose_prints_trajectory(fake_search, fake_consolidate,
                                   monkeypatch, capsys):
    monkeypatch.setattr("triage.cli.load_capture",
                        lambda n2, n4=None, sbi=None: SimpleNamespace(n4=None, 
                            n2={"flows": [reject_flow(1)]}, sbi=sbi))
    assert main(["analyze", "x.json", "--verbose"]) == 0
    err = capsys.readouterr().err
    assert "winning trajectory:" in err
    assert "action: inspect flows" in err
    assert "Flow 1 (2 message(s))" in err


def test_out_writes_same_json(fake_search, fake_consolidate, monkeypatch,
                              tmp_path, capsys):
    monkeypatch.setattr("triage.cli.load_capture",
                        lambda n2, n4=None, sbi=None: SimpleNamespace(n4=None, 
                            n2={"flows": [reject_flow(1)]}, sbi=sbi))
    out = tmp_path / "results.json"
    assert main(["analyze", "x.json", "--out", str(out)]) == 0
    results, _ = captured(capsys)
    assert json.loads(out.read_text()) == results


def test_unknown_command_is_usage_error(capsys):
    with pytest.raises(SystemExit):
        main(["frobnicate"])
    assert "invalid choice" in capsys.readouterr().err


# --- triage report (the offline re-renderer) ---------------------------


def saved_result(**overrides):
    result = {
        "flow_id": 1,
        "procedure": "Registration",
        "shape": "explicit reject",
        "detail": "cause code(s) observed: #111",
        "episode": EPISODE.model_dump(mode="json"),
        "reward": 0.9,
        "rollouts": 2,
        "trajectory": [["inspect flows", "Flow 1 (2 message(s))"]],
        "memory_wrote": True,
    }
    result.update(overrides)
    return result


def write_json(path, obj):
    path.write_text(json.dumps(obj, indent=2) + "\n")


@pytest.fixture
def no_graph(monkeypatch):
    monkeypatch.setattr("triage.cli.load_graph", lambda: None)


def test_report_subcommand_stdout_markdown(no_graph, tmp_path, capsys):
    results = tmp_path / "results.json"
    n2 = tmp_path / "capture_n2.json"
    write_json(results, [saved_result()])
    write_json(n2, {"flows": [reject_flow(1)]})
    assert main(["report", "--results", str(results), str(n2)]) == 0
    out = capsys.readouterr().out
    assert out.startswith("# Post-incident report — registration_reject\n")
    assert "**Flow:** 1 — Registration, explicit reject" in out
    assert "- [verified] 5GMMRegistrationReject @ 2.000s — cause #111" in out
    assert "## Timeline (flow 1)" in out
    assert "[1] inspect flows -> Flow 1 (2 message(s))" in out


def test_report_out_writes_same_markdown(no_graph, tmp_path, capsys):
    results = tmp_path / "results.json"
    n2 = tmp_path / "capture_n2.json"
    write_json(results, [saved_result()])
    write_json(n2, {"flows": [reject_flow(1)]})
    out = tmp_path / "report.md"
    assert main(["report", "--results", str(results), str(n2),
                 "-o", str(out)]) == 0
    assert out.read_text() == capsys.readouterr().out


def test_report_missing_results_file_exits_1(no_graph, tmp_path, capsys):
    n2 = tmp_path / "capture_n2.json"
    write_json(n2, {"flows": [reject_flow(1)]})
    assert main(["report", "--results", str(tmp_path / "nope.json"),
                 str(n2)]) == 1
    out = capsys.readouterr()
    assert out.out == ""
    assert "triage: error: cannot load" in out.err


def test_report_results_not_array_exits_1(no_graph, tmp_path, capsys):
    results = tmp_path / "results.json"
    n2 = tmp_path / "capture_n2.json"
    write_json(results, {"not": "an array"})
    write_json(n2, {"flows": [reject_flow(1)]})
    assert main(["report", "--results", str(results), str(n2)]) == 1
    out = capsys.readouterr()
    assert out.out == ""
    assert "is not a JSON array of results" in out.err


def test_report_bad_n2_exits_1(no_graph, tmp_path, capsys):
    results = tmp_path / "results.json"
    n2 = tmp_path / "capture_n2.json"
    write_json(results, [saved_result()])
    n2.write_text("not json{")
    assert main(["report", "--results", str(results), str(n2)]) == 1
    out = capsys.readouterr()
    assert out.out == ""
    assert "triage: error: cannot load" in out.err


def test_report_n4_optional(no_graph, tmp_path, capsys):
    results = tmp_path / "results.json"
    n2 = tmp_path / "capture_n2.json"
    n4 = tmp_path / "capture_n4.json"
    write_json(results, [saved_result()])
    write_json(n2, {"flows": [reject_flow(1)]})
    write_json(n4, {"messages": []})
    assert main(["report", "--results", str(results), str(n2)]) == 0
    assert main(["report", "--results", str(results), str(n2),
                 "--n4", str(n4)]) == 0
    assert capsys.readouterr().out.startswith("# Post-incident report")


def test_report_out_write_error_exits_1(no_graph, tmp_path, capsys):
    results = tmp_path / "results.json"
    n2 = tmp_path / "capture_n2.json"
    write_json(results, [saved_result()])
    write_json(n2, {"flows": [reject_flow(1)]})
    assert main(["report", "--results", str(results), str(n2),
                 "-o", str(tmp_path)]) == 1
    out = capsys.readouterr()
    assert out.out == ""
    assert "triage: error: cannot write" in out.err


def test_report_zero_incidents(no_graph, tmp_path, capsys):
    results = tmp_path / "results.json"
    n2 = tmp_path / "capture_n2.json"
    write_json(results, [])
    write_json(n2, {"flows": []})
    assert main(["report", "--results", str(results), str(n2)]) == 0
    assert "# Post-incident report — no incidents" in capsys.readouterr().out


# --- triage analyze --report -------------------------------------------


def test_analyze_report_flag_writes_report(no_graph, fake_search,
                                           fake_consolidate, monkeypatch,
                                           tmp_path, capsys):
    monkeypatch.setattr("triage.cli.load_capture",
                        lambda n2, n4=None, sbi=None: SimpleNamespace(
                            n2={"flows": [reject_flow(1)]}, n4=None,
                            sbi=sbi))
    report_path = tmp_path / "report.md"
    assert main(["analyze", "x.json",
                 "--report", str(report_path)]) == 0
    results, _ = captured(capsys)
    assert len(results) == 1
    text = report_path.read_text()
    assert text.startswith("# Post-incident report — registration_reject\n")
    assert "## Timeline (flow 1)" in text


def test_analyze_report_no_hypothesis(no_graph, fake_consolidate,
                                      monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("triage.cli.load_capture",
                        lambda n2, n4=None, sbi=None: SimpleNamespace(n4=None, 
                            n2={"flows": [reject_flow(1)]}, sbi=sbi))
    monkeypatch.setattr("triage.cli.run_lats",
                        lambda capture, incident, store=None, **kwargs:
                        SimpleNamespace(episode=None, reward=0.0, rollouts=10,
                                        trajectory=[]))
    report_path = tmp_path / "report.md"
    assert main(["analyze", "x.json",
                 "--report", str(report_path)]) == 0
    assert "no hypothesis (flow 1)" in report_path.read_text()


def test_analyze_report_zero_incidents(no_graph, monkeypatch, tmp_path,
                                       capsys):
    monkeypatch.setattr("triage.cli.load_capture",
                        lambda n2, n4=None, sbi=None: SimpleNamespace(n4=None, 
                            n2={"flows": [{"flow_id": 1, "messages": [],
                                           "procedures": [],
                                           "partial": False}]},
                            sbi=sbi))
    report_path = tmp_path / "report.md"
    assert main(["analyze", "x.json",
                 "--report", str(report_path)]) == 0
    results, _ = captured(capsys)
    assert results == []
    assert "# Post-incident report — no incidents" in report_path.read_text()


def test_analyze_report_write_error_exits_1(no_graph, fake_search,
                                            fake_consolidate, monkeypatch,
                                            tmp_path, capsys):
    monkeypatch.setattr("triage.cli.load_capture",
                        lambda n2, n4=None, sbi=None: SimpleNamespace(n4=None, 
                            n2={"flows": [reject_flow(1)]}, sbi=sbi))

    def boom(results, capture, path, graph=None):
        raise OSError("boom")
    monkeypatch.setattr("triage.cli.write_report", boom)
    assert main(["analyze", "x.json",
                 "--report", str(tmp_path / "report.md")]) == 1
    out = capsys.readouterr()
    assert out.out == ""
    assert "triage: error: cannot write" in out.err


def test_saved_result_has_trajectory_and_detail(fake_search,
                                                fake_consolidate,
                                                monkeypatch, capsys):
    monkeypatch.setattr("triage.cli.load_capture",
                        lambda n2, n4=None, sbi=None: SimpleNamespace(n4=None, 
                            n2={"flows": [reject_flow(1)]}, sbi=sbi))
    assert main(["analyze", "capture_n2.json"]) == 0
    results, _ = captured(capsys)
    result = results[0]
    assert result["trajectory"] == [["inspect flows", "Flow 1 (2 message(s))"]]
    assert result["detail"] == "cause code(s) observed: #111"


def n4_timeout_procedure():
    return {"kind": "session_establishment", "outcome": "timeout"}


def test_analyze_n4_incidents(fake_search, fake_consolidate, monkeypatch,
                              capsys, tmp_path):
    n4 = tmp_path / "capture_n4.json"
    n4.write_text(json.dumps({"messages": [], "procedures": [
        n4_timeout_procedure()]}) + "\n")
    monkeypatch.setattr("triage.cli.load_capture",
                        lambda n2, n4=None, sbi=None: SimpleNamespace(
                            n2={"flows": []},
                            n4=json.loads(Path(n4).read_text())
                            if n4 else None, sbi=None))
    assert main(["analyze", "capture_n2.json", "--n4", str(n4)]) == 0
    assert [flow_id for flow_id, _ in fake_search] == [None]
    results, err = captured(capsys)
    assert len(results) == 1
    result = results[0]
    assert result["plane"] == "n4"
    assert result["flow_id"] is None
    assert result["procedure"] == "session_establishment"
    assert result["shape"] == "no terminal message (timeout)"
    assert result["detail"] is None  # timeouts carry no detail, like SBI
    assert ("N4 session_establishment session_establishment "
            "(no terminal message (timeout))") in err


def test_flow_filter_drops_n4_incidents(fake_search, fake_consolidate,
                                        monkeypatch, capsys, tmp_path):
    n4 = tmp_path / "capture_n4.json"
    n4.write_text(json.dumps({"messages": [], "procedures": [
        n4_timeout_procedure()]}) + "\n")
    monkeypatch.setattr("triage.cli.load_capture",
                        lambda n2, n4=None, sbi=None: SimpleNamespace(
                            n2={"flows": [reject_flow(1)]},
                            n4=json.loads(Path(n4).read_text())
                            if n4 else None, sbi=None))
    assert main(["analyze", "capture_n2.json", "--n4", str(n4),
                 "--flow", "1"]) == 0
    assert [flow_id for flow_id, _ in fake_search] == [1]
