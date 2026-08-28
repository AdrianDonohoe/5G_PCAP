"""The tracer spine: handle checkpoints at the proposal and exits; approve /
reject resume in a fresh graph instance across invocations. Groq-free."""

import json
from pathlib import Path

import pytest

from dispatch.graph import build_graph, run_approval, run_to_approval

FIXTURES = Path(__file__).parent / "fixtures"
COMPOSE = """services:
  upf:
    image: oai-upf
"""


@pytest.fixture
def event():
    return json.loads((FIXTURES / "event_n4_timeout.json").read_text())


@pytest.fixture
def stub():
    return json.loads((FIXTURES / "stub_n4_timeout.json").read_text())


@pytest.fixture
def sandbox(tmp_path):
    (tmp_path / "core").mkdir()
    (tmp_path / "core" / "docker-compose.yml").write_text(COMPOSE)
    return tmp_path


@pytest.fixture
def ctx(tmp_path, sandbox):
    return {
        "state_path": tmp_path / "checkpoints.sqlite",
        "records_dir": tmp_path / "records",
        "sandbox_root": sandbox,
    }


def _graph(ctx, runner=None):
    return build_graph(ctx["state_path"], ctx["records_dir"],
                       ctx["sandbox_root"], runner=runner)


def _handle(ctx, event, stub):
    run_to_approval(_graph(ctx), event, stub)


def test_handle_checkpoints_and_writes_pending_record(ctx, event, stub):
    _handle(ctx, event, stub)
    record = ctx["records_dir"] / f'{event["incident_id"]}.md'
    assert record.exists()
    assert "Approval status: **pending**" in record.read_text()
    assert ctx["state_path"].exists() and ctx["state_path"].stat().st_size > 0


def test_handle_pauses_at_approval(ctx, event, stub):
    cg = _graph(ctx)
    run_to_approval(cg, event, stub)
    cfg = {"configurable": {"thread_id": event["incident_id"]}}
    assert cg.get_state(cfg).next != ()


def test_approve_dry_run_in_fresh_graph_instance(ctx, event, stub):
    _handle(ctx, event, stub)
    run_approval(_graph(ctx), event["incident_id"], "approve", execute=False)
    record = (ctx["records_dir"] / f'{event["incident_id"]}.md').read_text()
    assert "**approved (dry-run)**" in record
    assert "dry-run: docker compose" in record


def test_approve_execute_applies_through_injected_runner(ctx, event, stub):
    calls = []

    def fake(cmd, **kw):
        calls.append(cmd)
        return 0

    _handle(ctx, event, stub)
    run_approval(_graph(ctx, runner=fake), event["incident_id"],
                 "approve", execute=True)
    assert len(calls) == 1
    assert calls[0] == f"docker compose --project-directory {ctx['sandbox_root']}/core restart upf"
    record = (ctx["records_dir"] / f'{event["incident_id"]}.md').read_text()
    assert "**approved (executed)**" in record
    assert "executed: docker compose" in record


def test_approve_without_execute_never_invokes_runner(ctx, event, stub):
    calls = []

    def fake(cmd, **kw):
        calls.append(cmd)
        return 0

    _handle(ctx, event, stub)
    run_approval(_graph(ctx, runner=fake), event["incident_id"],
                 "approve", execute=False)
    assert calls == []


def test_reject_records_rejection(ctx, event, stub):
    _handle(ctx, event, stub)
    run_approval(_graph(ctx), event["incident_id"], "reject")
    record = (ctx["records_dir"] / f'{event["incident_id"]}.md').read_text()
    assert "**rejected**" in record
    assert "no commands applied" in record


def test_resume_unknown_incident_errors(ctx, event, stub):
    with pytest.raises(ValueError, match="no checkpoint"):
        run_approval(_graph(ctx), "never-existed", "approve", execute=False)


def test_resume_finished_incident_errors(ctx, event, stub):
    _handle(ctx, event, stub)
    run_approval(_graph(ctx), event["incident_id"], "approve", execute=False)
    with pytest.raises(ValueError, match="not awaiting approval"):
        run_approval(_graph(ctx), event["incident_id"], "approve",
                     execute=False)


def test_tampered_record_proposal_hash_refuses(ctx, event, stub):
    _handle(ctx, event, stub)
    record_path = ctx["records_dir"] / f'{event["incident_id"]}.md'
    tampered = record_path.read_text().replace("Proposal hash: `", "Proposal hash: `0")
    record_path.write_text(tampered)
    with pytest.raises(ValueError, match="hash mismatch"):
        run_approval(_graph(ctx), event["incident_id"], "approve", execute=False)


def test_observe_only_proposal_applies_nothing(ctx, event):
    stub_observe = {
        "evidence": [],
        "root_cause": "nothing actionable",
        "proposal": {"action": "observe_only", "args": {},
                     "justification": "watch and re-run the capture later"},
    }
    _handle(ctx, event, stub_observe)
    calls = []

    def fake(cmd, **kw):
        calls.append(cmd)
        return 0

    run_approval(_graph(ctx, runner=fake), event["incident_id"],
                 "approve", execute=True)
    assert calls == []
    record = (ctx["records_dir"] / f'{event["incident_id"]}.md').read_text()
    assert "observe only" in record
