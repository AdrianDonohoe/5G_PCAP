"""triage analyze end-to-end via cli.main with stubbed search/memory/loading
(ADR-0002: the suite never calls Groq)."""

import json
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
                        lambda n2, n4=None: SimpleNamespace(
                            n2={"flows": [reject_flow(1)]}))
    assert main(["analyze", "capture_n2.json"]) == 0
    results, err = captured(capsys)
    assert len(results) == 1
    result = results[0]
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
                        lambda n2, n4=None: SimpleNamespace(
                            n2={"flows": [{"flow_id": 1, "messages": [],
                                           "procedures": [], "partial": False}]}))
    assert main(["analyze", "golden.json"]) == 0
    results, err = captured(capsys)
    assert results == []
    assert "no failed Incidents detected" in err


def test_flow_filter_runs_only_matching_incident(fake_search,
                                                 fake_consolidate,
                                                 monkeypatch, capsys):
    monkeypatch.setattr("triage.cli.load_capture",
                        lambda n2, n4=None: SimpleNamespace(
                            n2={"flows": [reject_flow(1), reject_flow(2)]}))
    assert main(["analyze", "x.json", "--flow", "2"]) == 0
    assert [flow_id for flow_id, _ in fake_search] == [2]
    results, _ = captured(capsys)
    assert [r["flow_id"] for r in results] == [2]


def test_flow_filter_matching_none(monkeypatch, capsys):
    monkeypatch.setattr("triage.cli.load_capture",
                        lambda n2, n4=None: SimpleNamespace(
                            n2={"flows": [reject_flow(1)]}))
    assert main(["analyze", "x.json", "--flow", "9"]) == 0
    results, err = captured(capsys)
    assert results == []
    assert "--flow 9 matched none" in err


def test_load_error_exits_1(monkeypatch, capsys):
    def boom(n2, n4=None):
        raise ValueError("boom")
    monkeypatch.setattr("triage.cli.load_capture", boom)
    assert main(["analyze", "bad.json"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "triage: error: cannot load bad.json: boom" in captured.err


def test_groq_key_error_exits_1(fake_consolidate, monkeypatch, capsys):
    monkeypatch.setattr("triage.cli.load_capture",
                        lambda n2, n4=None: SimpleNamespace(
                            n2={"flows": [reject_flow(1)]}))

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
                        lambda n2, n4=None: SimpleNamespace(
                            n2={"flows": [reject_flow(1)]}))
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
                        lambda n2, n4=None: SimpleNamespace(
                            n2={"flows": [reject_flow(1)]}))
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
                        lambda n2, n4=None: SimpleNamespace(
                            n2={"flows": [reject_flow(1)]}))
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
                        lambda n2, n4=None: SimpleNamespace(
                            n2={"flows": [reject_flow(1)]}))
    assert main(["analyze", "x.json", "--verbose"]) == 0
    err = capsys.readouterr().err
    assert "winning trajectory:" in err
    assert "action: inspect flows" in err
    assert "Flow 1 (2 message(s))" in err


def test_out_writes_same_json(fake_search, fake_consolidate, monkeypatch,
                              tmp_path, capsys):
    monkeypatch.setattr("triage.cli.load_capture",
                        lambda n2, n4=None: SimpleNamespace(
                            n2={"flows": [reject_flow(1)]}))
    out = tmp_path / "results.json"
    assert main(["analyze", "x.json", "--out", str(out)]) == 0
    results, _ = captured(capsys)
    assert json.loads(out.read_text()) == results


def test_unknown_command_is_usage_error(capsys):
    with pytest.raises(SystemExit):
        main(["frobnicate"])
    assert "invalid choice" in capsys.readouterr().err
