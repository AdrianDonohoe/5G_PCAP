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
    # The runbooks dir is patched too, so the CLI tests never load the
    # committed seed runbook — the wiring test below drops one in
    # explicitly. The close-time drafts stage in a patched proposed dir.
    monkeypatch.setattr(cli, "RUNBOOKS_DIR", tmp_path / "runbooks")
    monkeypatch.setattr(cli, "PROPOSED_RUNBOOKS_DIR", tmp_path / "proposed")
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
    for name in ("handle", "detect-kpi", "approve", "reject", "close"):
        assert name in out


# The CLI builds its graph without a proposer seam; the happy approve
# paths inject the selection one level down, at the proposal default
# (the conftest blanket has already stubbed it to raise — ADR-0002).

SELECTION = {"action": "restart_nf", "args": {"nf": "upf"},
             "justification": "Restarting the UPF clears the stuck "
                              "session state."}


def _inject_proposal(monkeypatch, selection=None):
    monkeypatch.setattr(proposal_mod, "default_propose",
                        lambda: (lambda incident, root_cause:
                                 dict(selection or SELECTION)))


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


# --- Runbooks: the CLI loads the committed dir and passes it through ---

# The specialist seams replace the stub's evidence with nothing, so the
# CLI path matches runbooks on the procedure alone — the procedure-only
# +2 still clears the threshold, and the proposer sees the context.
RUNBOOK_MD = """---
slug: n4-timeout-restart-upf
title: Restart the UPF on an N4 timeout
procedure: n4_upf_timeout
symptoms:
  nf: upf
steps:
  - Confirm the UPF logged the request.
resolution:
  action: restart_nf
  args:
    nf: "{nf}"
---
"""


def test_handle_prepends_matching_runbook_context(tmp_state, monkeypatch):
    seen = []

    def propose(incident, root_cause):
        seen.append(incident)
        return dict(SELECTION)

    monkeypatch.setattr(proposal_mod, "default_propose", lambda: propose)
    (tmp_state / "runbooks").mkdir()
    (tmp_state / "runbooks" / "n4-timeout.md").write_text(RUNBOOK_MD)
    cli.main(["handle", EVENT, "--stub", STUB])
    assert "Runbooks retrieved from procedural memory" in seen[0]


def test_handle_without_runbooks_leaves_the_description_untouched(
        tmp_state, monkeypatch):
    seen = []

    def propose(incident, root_cause):
        seen.append(incident)
        return dict(SELECTION)

    monkeypatch.setattr(proposal_mod, "default_propose", lambda: propose)
    cli.main(["handle", EVENT, "--stub", STUB])
    assert seen == [json.loads(Path(EVENT).read_text())["description"]]


# --- Close: the Outcome and the deterministic Runbook draft (spec #33) ---

OBSERVE = {"action": "observe_only", "args": {},
           "justification": "Watch the lab before touching anything."}


def _close_ready(monkeypatch, selection=None):
    # The executor's subprocess reference is patched (not the shared
    # subprocess module) so only executor commands are recorded — the
    # same seam test_approve_execute_applies uses.
    calls = []
    monkeypatch.setattr(executor_mod, "subprocess",
                        types.SimpleNamespace(
                            run=lambda cmd, **kw: calls.append(cmd)))
    _inject_proposal(monkeypatch, selection)
    cli.main(["handle", EVENT, "--stub", STUB])
    assert cli.main(["approve", INCIDENT, "--execute"]) == 0
    return calls


def test_close_resolved_appends_outcome_and_drafts(tmp_state, capsys,
                                                   monkeypatch):
    from dispatch.runbook import parse_runbook

    _close_ready(monkeypatch)
    assert cli.main(["close", INCIDENT, "--outcome", "resolved",
                     "--evidence", "detect-kpi returned the Golden "
                     "baseline"]) == 0
    out = capsys.readouterr().out
    record = (tmp_state / "records" / f"{INCIDENT}.md").read_text()
    assert "## Outcome" in record
    assert "**resolved**" in record
    assert "detect-kpi returned the Golden baseline" in record
    # The suggested confirmation check uses the event's capture names.
    assert "Suggested confirmation check" in out
    assert "dispatch detect-kpi n4_upf_timeout.pcap" in out
    # The deterministic draft (no LLM call) is staged with a traceable
    # name and its concrete args copied literally.
    draft = tmp_state / "proposed" / "n4_upf_timeout-inc-n4-upf-timeout-1.md"
    assert draft.exists()
    assert "+slug: n4_upf_timeout-inc-n4-upf-timeout-1" in out
    rb = parse_runbook(draft)
    assert rb.procedure == "n4_upf_timeout"
    assert rb.resolution.args == {"nf": "upf"}
    from dispatch.memory import EpisodeStore

    stored = EpisodeStore(tmp_state / "episodes.jsonl").load()
    assert stored[0].outcome == "resolved"
    assert stored[0].outcome_evidence == \
        "detect-kpi returned the Golden baseline"
    assert "closed incident" in out


def test_close_unresolved_writes_outcome_without_draft(tmp_state, capsys,
                                                       monkeypatch):
    _close_ready(monkeypatch)
    assert cli.main(["close", INCIDENT, "--outcome", "unresolved"]) == 0
    record = (tmp_state / "records" / f"{INCIDENT}.md").read_text()
    assert "**unresolved**" in record
    assert not (tmp_state / "proposed").exists()
    assert "closed incident" in capsys.readouterr().out


def test_close_refused_while_awaiting_approval(tmp_state, capsys,
                                              monkeypatch):
    _inject_proposal(monkeypatch)
    cli.main(["handle", EVENT, "--stub", STUB])
    assert cli.main(["close", INCIDENT, "--outcome", "resolved"]) == 1
    assert "awaiting approval" in capsys.readouterr().err


def test_close_refused_for_dry_run_approval(tmp_state, capsys, monkeypatch):
    _inject_proposal(monkeypatch)
    cli.main(["handle", EVENT, "--stub", STUB])
    assert cli.main(["approve", INCIDENT]) == 0
    assert cli.main(["close", INCIDENT, "--outcome", "resolved"]) == 1
    assert "not approved for execution" in capsys.readouterr().err


def test_close_refused_for_rejected(tmp_state, capsys):
    cli.main(["handle", EVENT, "--stub", STUB])
    assert cli.main(["reject", INCIDENT]) == 0
    assert cli.main(["close", INCIDENT, "--outcome", "resolved"]) == 1
    assert "not approved for execution" in capsys.readouterr().err


def test_close_unknown_incident_errors(tmp_state, capsys):
    assert cli.main(["close", "never-existed", "--outcome", "resolved"]) == 1
    assert "no checkpoint" in capsys.readouterr().err


def test_close_refused_when_already_closed(tmp_state, capsys, monkeypatch):
    _close_ready(monkeypatch)
    assert cli.main(["close", INCIDENT, "--outcome", "resolved"]) == 0
    assert cli.main(["close", INCIDENT, "--outcome", "resolved"]) == 1
    assert "already closed" in capsys.readouterr().err


def test_close_observe_only_writes_outcome_without_draft(tmp_state, capsys,
                                                         monkeypatch):
    _close_ready(monkeypatch, OBSERVE)
    assert cli.main(["close", INCIDENT, "--outcome", "resolved"]) == 0
    record = (tmp_state / "records" / f"{INCIDENT}.md").read_text()
    assert "**resolved**" in record
    assert not (tmp_state / "proposed").exists()


def test_close_with_matching_runbook_skips_the_draft(tmp_state, capsys,
                                                     monkeypatch):
    (tmp_state / "runbooks").mkdir()
    (tmp_state / "runbooks" / "n4-timeout.md").write_text(RUNBOOK_MD)
    _close_ready(monkeypatch)
    assert cli.main(["close", INCIDENT, "--outcome", "resolved"]) == 0
    assert not (tmp_state / "proposed").exists()
    assert "## Outcome" in \
        (tmp_state / "records" / f"{INCIDENT}.md").read_text()
    # The loop never edits the committed runbooks (spec #33).
    assert (tmp_state / "runbooks" / "n4-timeout.md").read_text() == RUNBOOK_MD


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
