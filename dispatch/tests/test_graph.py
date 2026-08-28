"""The tracer spine: handle checkpoints at the proposal and exits; approve /
reject resume in a fresh graph instance across invocations. Groq-free."""

import json
import types
from pathlib import Path

import pytest

import dispatch.kpi as kpi_mod
from _helpers import make_kpi_runner, make_log_runner, make_triage_runner
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


def _graph(ctx, runner=None, kpi_runner=None, triage_runner=None):
    return build_graph(ctx["state_path"], ctx["records_dir"],
                       ctx["sandbox_root"], runner=runner,
                       kpi_runner=kpi_runner, triage_runner=triage_runner)


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


# --- the KPI specialist node: real evidence replaces the stub's kpi items ---

# The committed Golden baseline is the comparator's contract — tests read
# it directly so they track baseline regeneration, never a hand copy.
KPI_GOLDEN = kpi_mod.load_golden()


def test_kpi_node_replaces_stub_items_with_grounded_evidence(ctx, event, stub):
    event["captures"] = {"n2": "degraded_n2.pcap"}
    export = {"kpis": dict(KPI_GOLDEN, procedure_success_rate=0.8,
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
    calls = []
    graph = build_graph(ctx["state_path"], ctx["records_dir"],
                        ctx["sandbox_root"],
                        kpi_runner=make_kpi_runner(export, calls))
    run_to_approval(graph, event, stub)
    record = (ctx["records_dir"] / f'{event["incident_id"]}.md').read_text()
    assert "kpi.procedure_success_rate=0.8" in record
    assert "nas_cause 7" in record
    assert "N4 latency missing" not in record  # stub kpi item replaced
    assert len(calls) == 1


def test_kpi_node_without_n2_capture_runs_nothing(ctx, event, stub):
    event["captures"] = {}  # the fixture now carries n2 — strip it here
    calls = []
    run_to_approval(_graph(ctx, kpi_runner=lambda cmd, **kw: calls.append(cmd)),
                    event, stub)
    assert calls == []
    record = (ctx["records_dir"] / f'{event["incident_id"]}.md').read_text()
    assert "N4 latency missing" not in record


# --- the PCAP specialist node: real evidence replaces the stub's pcap items ---

def test_pcap_node_replaces_stub_items_with_grounded_evidence(ctx, event, stub,
                                                              monkeypatch):
    export = {"kpis": {}, "flows": [], "unassociated": [],
              "n4": {"messages": [
                  {"ts": 1749999950.0, "name": "PFCP Session Establishment "
                   "Request", "cause_code": None, "flow_id": None}]},
              "sbi": {"messages": []}}
    # Patch the kpi module's subprocess reference (not the shared
    # subprocess module, which the log seam also uses) so only the KPI
    # agent's 5gcap command is captured.
    monkeypatch.setattr(kpi_mod, "subprocess",
                        types.SimpleNamespace(run=make_kpi_runner(export)))
    results = [{"plane": "n4", "flow_id": None, "procedure": "session_"
                "establishment", "shape": "no terminal message (timeout)",
                "detail": None, "episode": {
                    "incident_type": "n4_upf_timeout", "narrative": "timeout",
                    "cited_evidence": [
                        {"message": "PFCP Session Establishment Request",
                         "cause": None, "ts": 1749999950.0},
                        {"message": "FabricatedRequest", "cause": None,
                         "ts": 1749999950.0}]}}]
    calls = []
    graph = build_graph(ctx["state_path"], ctx["records_dir"],
                        ctx["sandbox_root"],
                        triage_runner=make_triage_runner(results, calls))
    run_to_approval(graph, event, stub)
    record = (ctx["records_dir"] / f'{event["incident_id"]}.md').read_text()
    assert "PFCP Session Establishment Request" in record
    assert "n4:1" in record
    assert "no response by capture end" not in record  # stub pcap replaced
    assert "FabricatedRequest" not in record  # hallucinated, never recorded
    assert len(calls) == 1


# --- the Log specialist node: real evidence replaces the stub's log items ---

def test_log_node_replaces_stub_items_with_grounded_evidence(ctx, event,
                                                             stub):
    windowed = (FIXTURES / "core_logs_n4_timeout.txt").read_text()
    line = ("upf     | 2025-06-15T15:05:01.510724553Z [open5gs-upf] INFO "
            "[upf] PFCP[0] Session Establishment Request "
            "(../src/upf/pfcp-sm.c:225)")

    def extract(text, event):
        return [{"kind": "request unanswered",
                 "entry": "UPF logs the request but never answers",
                 "keys": {"nf": "upf"}, "citation": line}]

    calls = []
    graph = build_graph(ctx["state_path"], ctx["records_dir"],
                        ctx["sandbox_root"],
                        log_runner=make_log_runner(windowed, calls),
                        extractor=extract)
    run_to_approval(graph, event, stub)
    record = (ctx["records_dir"] / f'{event["incident_id"]}.md').read_text()
    assert line in record                # grounded, cited by its exact line
    assert "UPF stuck" not in record     # stub log item replaced
    assert "upf.log:" not in record
    assert "sandbox/core/log/upf.log:1833" not in record
    assert len(calls) == 1
