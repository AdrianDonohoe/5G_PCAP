"""The CLI seam: handle → (fresh invocation) approve/reject, end to end."""

import json
import types
from pathlib import Path

import pytest

import dispatch.cli as cli
import dispatch.executor as executor_mod
import dispatch.kpi as kpi_mod
import dispatch.proposal as proposal_mod
from _helpers import make_kpi_runner

FIXTURES = Path(__file__).parent / "fixtures"
EVENT = str(FIXTURES / "event_n4_timeout.json")
STUB = str(FIXTURES / "stub_n4_timeout.json")
INCIDENT = "inc-n4-upf-timeout-1"


@pytest.fixture
def tmp_state(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "STATE_PATH", tmp_path / "checkpoints.sqlite")
    monkeypatch.setattr(cli, "RECORDS_DIR", tmp_path / "records")
    return tmp_path


def test_handle_writes_record_and_checkpoint(tmp_state, capsys):
    assert cli.main(["handle", EVENT, "--stub", STUB]) == 0
    record = tmp_state / "records" / f"{INCIDENT}.md"
    assert record.exists()
    assert "**pending**" in record.read_text()
    # No live proposal selection behind the seam: the record says so
    # honestly instead of inventing one (AC-1).
    assert "- (no proposal produced)" in record.read_text()
    assert (tmp_state / "checkpoints.sqlite").exists()


def test_handle_requires_stub(tmp_state, capsys):
    assert cli.main(["handle", EVENT]) == 1
    assert "stub" in capsys.readouterr().err


def test_handle_rejects_malformed_event(tmp_state, capsys):
    bad = tmp_state / "bad.json"
    bad.write_text(json.dumps({"incident_id": "x"}))
    assert cli.main(["handle", str(bad), "--stub", STUB]) == 1


def test_handle_refuses_duplicate_incident(tmp_state, capsys):
    assert cli.main(["handle", EVENT, "--stub", STUB]) == 0
    assert cli.main(["handle", EVENT, "--stub", STUB]) == 1
    assert "already" in capsys.readouterr().err


def test_help_lists_reserved_subcommands(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    out = capsys.readouterr().out
    for name in ("handle", "detect-kpi", "approve", "reject"):
        assert name in out


# The CLI builds its graph without a proposer seam; the happy approve
# paths inject the selection one level down, at the proposal default
# (the conftest blanket has already stubbed it to raise — ADR-0002).

SELECTION = {"action": "restart_nf", "args": {"nf": "upf"},
             "justification": "Restarting the UPF clears the stuck "
                              "session state."}


def _inject_proposal(monkeypatch):
    monkeypatch.setattr(proposal_mod, "default_propose",
                        lambda: (lambda incident, root_cause:
                                 dict(SELECTION)))


def test_approve_without_proposal_errors(tmp_state, capsys):
    # With the live selection stubbed, the honest record has no
    # proposal, and approve fails loudly instead of executing anything
    # (AC-1).
    cli.main(["handle", EVENT, "--stub", STUB])
    assert cli.main(["approve", INCIDENT]) == 1
    assert "no proposal" in capsys.readouterr().err
    record = (tmp_state / "records" / f"{INCIDENT}.md").read_text()
    assert "**pending**" in record


def test_approve_resumes_across_invocations_dry_run(tmp_state, capsys,
                                                    monkeypatch):
    _inject_proposal(monkeypatch)
    cli.main(["handle", EVENT, "--stub", STUB])
    assert cli.main(["approve", INCIDENT]) == 0
    assert "restart upf" in capsys.readouterr().out
    record = (tmp_state / "records" / f"{INCIDENT}.md").read_text()
    assert "**approved (dry-run)**" in record


def test_approve_execute_applies(tmp_state, monkeypatch):
    calls = []
    # Patch the executor's subprocess reference (not the shared subprocess
    # module, which the specialist seams also use) so only executor
    # commands are recorded.
    monkeypatch.setattr(executor_mod, "subprocess",
                        types.SimpleNamespace(
                            run=lambda cmd, **kw: calls.append(cmd)))
    _inject_proposal(monkeypatch)
    cli.main(["handle", EVENT, "--stub", STUB])
    assert cli.main(["approve", INCIDENT, "--execute"]) == 0
    assert len(calls) == 1
    assert "restart upf" in calls[0]
    record = (tmp_state / "records" / f"{INCIDENT}.md").read_text()
    assert "**approved (executed)**" in record


def test_reject_records_rejection(tmp_state):
    cli.main(["handle", EVENT, "--stub", STUB])
    assert cli.main(["reject", INCIDENT]) == 0
    record = (tmp_state / "records" / f"{INCIDENT}.md").read_text()
    assert "**rejected**" in record


def test_approve_writes_episode_beside_the_checkpoint(tmp_state,
                                                     monkeypatch):
    # The Episode store follows STATE_PATH, so the CLI's memory artifacts
    # land in the same state dir as the checkpoint — and the tmp_state
    # patch keeps the suite from ever touching the real store.
    from dispatch.memory import EpisodeStore

    _inject_proposal(monkeypatch)
    cli.main(["handle", EVENT, "--stub", STUB])
    assert cli.main(["approve", INCIDENT]) == 0
    stored = EpisodeStore(tmp_state / "episodes.jsonl").load()
    assert len(stored) == 1
    assert stored[0].incident_id == INCIDENT
    assert stored[0].decision == "approved-dry-run"
    assert stored[0].action == "restart_nf"


def test_approve_unknown_incident_errors(tmp_state, capsys):
    assert cli.main(["approve", "never-existed"]) == 1
    assert "no checkpoint" in capsys.readouterr().err


# --- detect-kpi: the comparator subcommand at the process boundary ---

# The committed Golden baseline is the comparator's contract — tests read
# it directly so they track baseline regeneration, never a hand copy.
GOLDEN = kpi_mod.load_golden()


def _healthy_export():
    return {"kpis": GOLDEN, "flows": [], "n4": {"messages": []},
            "sbi": {"messages": []}}


def _degraded_export():
    return {"kpis": dict(GOLDEN, procedure_success_rate=0.8,
                         procedure_successes=4, procedure_failures=1),
            "flows": [{"flow_id": 1, "procedures": [],
                       "messages": [{"ts": 1750000000.0,
                                     "nas": "5GMMRegistrationReject",
                                     "nas_inner": None,
                                     "nas_cause": {"code": 7,
                                                   "name": "5GS services "
                                                           "not allowed"},
                                     "unparsed": None}]}],
            "n4": {"messages": []}, "sbi": {"messages": []}}


def _fake_5gcap(monkeypatch, export, returncode=0):
    calls = []
    fake = make_kpi_runner(export, calls, returncode=returncode)
    monkeypatch.setattr(kpi_mod.subprocess, "run", fake)
    return calls


def test_detect_kpi_healthy_exits_0_and_emits_nothing(capsys, monkeypatch):
    _fake_5gcap(monkeypatch, _healthy_export())
    assert cli.main(["detect-kpi", "n2.pcap", "--sbi", "sbi.pcap",
                     "--n4", "n4.pcap"]) == 0
    assert capsys.readouterr().out == ""


def test_detect_kpi_degraded_emits_alarm_event(capsys, monkeypatch):
    calls = _fake_5gcap(monkeypatch, _degraded_export())
    assert cli.main(["detect-kpi", "n2.pcap"]) == 0
    out = capsys.readouterr().out
    event = json.loads(out)
    assert event["source"] == "kpi"
    assert "procedure_success_rate" in event["description"]
    assert "5GMMRegistrationReject nas_cause 7" in event["description"]
    assert event["captures"] == {"n2": "n2.pcap"}
    assert "5gcap analyze" in calls[0]


def test_detect_kpi_analyze_failure_exits_1(capsys, monkeypatch):
    _fake_5gcap(monkeypatch, {}, returncode=1)
    assert cli.main(["detect-kpi", "n2.pcap"]) == 1
    assert "error" in capsys.readouterr().err


def test_detect_kpi_export_without_kpis_exits_1(capsys, monkeypatch):
    _fake_5gcap(monkeypatch, {"messages": []})
    assert cli.main(["detect-kpi", "n4-disguised.pcap"]) == 1
    assert "no kpis" in capsys.readouterr().err
