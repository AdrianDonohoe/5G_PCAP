"""The tracer spine: handle checkpoints at the proposal and exits; approve /
reject resume in a fresh graph instance across invocations. Groq-free."""

import json
import types
from pathlib import Path

import pytest

import dispatch.kpi as kpi_mod
from _helpers import (make_kpi_runner, make_log_runner, make_proposer,
                      make_triage_runner)
from dispatch.executor import proposal_hash
from dispatch.graph import build_graph, run_approval, run_to_approval
from dispatch.memory import Episode, EpisodeStore, EvidenceKey
from dispatch.root_cause import Tree, make_execute
from dispatch.runbook import Runbook

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


# The proposal seam's canned selections: the LLM's role is choosing from
# the fixed five-action vocabulary, so flow tests inject that selection
# (the spec's stub pattern). The nf must be in the test COMPOSE above.
CANNED_PROPOSAL = {"action": "restart_nf", "args": {"nf": "upf"},
                   "justification": "Restarting the UPF clears the "
                                    "stuck session state."}
INVALID_SELECTION = {"action": "reboot_the_lab", "args": {},
                     "justification": "whatever"}


def _graph(ctx, runner=None, kpi_runner=None, triage_runner=None,
           proposer=None, episodes=None, search=None):
    return build_graph(ctx["state_path"], ctx["records_dir"],
                       ctx["sandbox_root"], runner=runner,
                       kpi_runner=kpi_runner, triage_runner=triage_runner,
                       proposer=proposer or make_proposer(CANNED_PROPOSAL),
                       episodes=episodes, search=search)


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
    observe = make_proposer(
        {"action": "observe_only", "args": {},
         "justification": "watch and re-run the capture later"})
    run_to_approval(_graph(ctx, proposer=observe), event, {"evidence": []})
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


# --- the Investigate node: the root-cause search replaces the stub ---

def test_investigate_node_replaces_stub_root_cause(ctx, event, stub):
    windowed = (FIXTURES / "core_logs_n4_timeout.txt").read_text()
    line = ("upf     | 2025-06-15T15:05:01.510724553Z [open5gs-upf] INFO "
            "[upf] PFCP[0] Session Establishment Request "
            "(../src/upf/pfcp-sm.c:225)")
    narrative = "The UPF logged the request and never answered it."

    def extract(text, event):
        return [{"kind": "request unanswered",
                 "entry": "UPF logs the request but never answers",
                 "keys": {"nf": "upf"}, "citation": line}]

    # The spec's stub-injected Tree pattern at the graph seam: a real
    # triage Tree with canned expand/evaluate steps and the Dispatcher's
    # execute over the grounded log item the node will hold.
    grounded_item = {"source": "log", "kind": "request unanswered",
                     "ts": 1749999901.510724,
                     "entry": "UPF logs the request but never answers",
                     "cause": None, "endpoints": None,
                     "keys": {"nf": "upf"}, "citation": line}

    def expand(objective, trajectory, n):
        assert line in objective        # the objective names the evidence
        return ["finalize " + json.dumps(
            {"narrative": narrative,
             "cited_evidence": [{"citation": line}]})]

    def evaluate(objective, trajectory):
        return types.SimpleNamespace(reward=1.0, status="complete",
                                     reflection="grounded")

    tree = Tree(expand=expand, evaluate=evaluate,
                execute=make_execute([grounded_item], []))

    graph = build_graph(ctx["state_path"], ctx["records_dir"],
                        ctx["sandbox_root"],
                        log_runner=make_log_runner(windowed),
                        extractor=extract,
                        search=lambda objective: tree.run(objective).episode)
    run_to_approval(graph, event, stub)
    record = (ctx["records_dir"] / f'{event["incident_id"]}.md').read_text()
    assert "## Root cause" in record
    assert narrative in record          # the winning trajectory's narrative


# --- the Propose node: real selection over the fixed vocabulary (#30) ---

def test_propose_node_replaces_stub_proposal(ctx, event, stub):
    # The seam injects a selection smuggling fabricated "commands" and
    # "hash" keys — the recorded commands come from the Executor's
    # deterministic templates, never LLM text (AC-2).
    calls = []
    propose = make_proposer(
        dict(CANNED_PROPOSAL, commands=["rm -rf /"], hash="fake"), calls)
    graph = build_graph(ctx["state_path"], ctx["records_dir"],
                        ctx["sandbox_root"], proposer=propose)
    run_to_approval(graph, event, stub)
    record = (ctx["records_dir"] / f'{event["incident_id"]}.md').read_text()
    assert "Restarting the UPF clears the stuck session state." in record
    template = (f"docker compose --project-directory "
                f"{ctx['sandbox_root']}/core restart upf")
    assert template in record             # template-rendered, never LLM text
    assert "rm -rf" not in record
    assert "Proposal hash: `" in record
    assert len(calls) == 1
    assert calls[0][0] == event["description"]


def test_invalid_selection_yields_no_proposal(ctx, event, stub):
    # AC-1: a selection outside the fixed vocabulary produces no
    # proposal, and the record says so honestly.
    propose = make_proposer(INVALID_SELECTION)
    run_to_approval(_graph(ctx, proposer=propose), event, stub)
    record = (ctx["records_dir"] / f'{event["incident_id"]}.md').read_text()
    assert "- (no proposal produced)" in record
    assert "**pending**" in record
    with pytest.raises(ValueError, match="nothing to execute"):
        run_approval(_graph(ctx, proposer=propose), event["incident_id"],
                     "approve", execute=False)


def test_reject_without_proposal_records_rejection(ctx, event, stub):
    propose = make_proposer(INVALID_SELECTION)
    run_to_approval(_graph(ctx, proposer=propose), event, stub)
    run_approval(_graph(ctx, proposer=propose), event["incident_id"],
                 "reject")
    record = (ctx["records_dir"] / f'{event["incident_id"]}.md').read_text()
    assert "**rejected**" in record
    assert "no commands applied" in record


def test_invalid_args_yield_no_proposal(ctx, event, stub):
    # The Executor render rail validates args against the sandbox
    # allowlists (nf outside the core compose here); a selection outside
    # them yields no proposal, the same as an invalid action.
    def propose(incident, root_cause):
        return {"action": "restart_nf", "args": {"nf": "smf"},
                "justification": "restart the session manager"}

    run_to_approval(_graph(ctx, proposer=propose), event, stub)
    record = (ctx["records_dir"] / f'{event["incident_id"]}.md').read_text()
    assert "- (no proposal produced)" in record


def test_full_audit_trail_end_to_end(ctx, event, stub):
    # AC-3: handle → approve --execute on the n4_upf_timeout event with
    # the log specialist, the root-cause search and the proposal
    # selection real behind their seams records the full audit trail:
    # grounded evidence, root cause, proposal, hash and execution log.
    windowed = (FIXTURES / "core_logs_n4_timeout.txt").read_text()
    line = ("upf     | 2025-06-15T15:05:01.510724553Z [open5gs-upf] INFO "
            "[upf] PFCP[0] Session Establishment Request "
            "(../src/upf/pfcp-sm.c:225)")
    narrative = "The UPF logged the request and never answered it."

    def extract(text, event):
        return [{"kind": "request unanswered",
                 "entry": "UPF logs the request but never answers",
                 "keys": {"nf": "upf"}, "citation": line}]

    grounded_item = {"source": "log", "kind": "request unanswered",
                     "ts": 1749999901.510724,
                     "entry": "UPF logs the request but never answers",
                     "cause": None, "endpoints": None,
                     "keys": {"nf": "upf"}, "citation": line}

    def expand(objective, trajectory, n):
        assert line in objective
        return ["finalize " + json.dumps(
            {"narrative": narrative,
             "cited_evidence": [{"citation": line}]})]

    def evaluate(objective, trajectory):
        return types.SimpleNamespace(reward=1.0, status="complete",
                                     reflection="grounded")

    tree = Tree(expand=expand, evaluate=evaluate,
                execute=make_execute([grounded_item], []))

    def propose(incident, root_cause):
        assert root_cause == narrative   # the proposal sees the root cause
        return dict(CANNED_PROPOSAL)

    calls = []

    def fake(cmd, **kw):
        calls.append(cmd)
        return 0

    graph = build_graph(ctx["state_path"], ctx["records_dir"],
                        ctx["sandbox_root"], runner=fake,
                        log_runner=make_log_runner(windowed),
                        extractor=extract,
                        search=lambda objective: tree.run(objective).episode,
                        proposer=propose)
    run_to_approval(graph, event, stub)
    run_approval(_graph(ctx, runner=fake), event["incident_id"],
                 "approve", execute=True)
    template = (f"docker compose --project-directory "
                f"{ctx['sandbox_root']}/core restart upf")
    assert len(calls) == 1
    assert calls[0] == template
    record = (ctx["records_dir"] / f'{event["incident_id"]}.md').read_text()
    assert line in record                          # grounded log evidence
    assert "## Root cause" in record
    assert narrative in record
    assert "Restarting the UPF clears the stuck session state." in record
    assert template in record
    assert "Proposal hash: `" in record
    assert "**approved (executed)**" in record
    assert "executed: docker compose" in record    # the full audit trail


# --- Episodic memory: the Episode write at decision time (spec #33) ---

def _episodes_path(ctx):
    return ctx["state_path"].parent / "episodes.jsonl"


def test_execute_writes_episode_on_dry_run_approve(ctx, event, stub):
    episodes = EpisodeStore(_episodes_path(ctx))
    run_to_approval(_graph(ctx, episodes=episodes), event, stub)
    run_approval(_graph(ctx, episodes=episodes), event["incident_id"],
                 "approve", execute=False)
    stored = EpisodeStore(_episodes_path(ctx)).load()
    assert len(stored) == 1
    ep = stored[0]
    assert ep.incident_id == event["incident_id"]
    assert ep.procedure == "n4_upf_timeout"
    assert ep.decision == "approved-dry-run"
    assert ep.action == "restart_nf"
    assert ep.justification == CANNED_PROPOSAL["justification"]
    # The blanket-stubbed specialists produced no evidence and no root
    # cause — the episode records the honest fallbacks.
    assert ep.evidence_keys == [] and ep.causes == []
    assert ep.narrative == ""


def test_execute_writes_episode_on_reject(ctx, event, stub):
    episodes = EpisodeStore(_episodes_path(ctx))
    run_to_approval(_graph(ctx, episodes=episodes), event, stub)
    run_approval(_graph(ctx, episodes=episodes), event["incident_id"],
                 "reject")
    stored = EpisodeStore(_episodes_path(ctx)).load()
    assert len(stored) == 1
    assert stored[0].decision == "rejected"


def test_execute_writes_episode_with_evidence_keys_on_execute(ctx, event,
                                                             stub):
    windowed = (FIXTURES / "core_logs_n4_timeout.txt").read_text()
    line = ("upf     | 2025-06-15T15:05:01.510724553Z [open5gs-upf] INFO "
            "[upf] PFCP[0] Session Establishment Request "
            "(../src/upf/pfcp-sm.c:225)")

    def extract(text, event):
        return [{"kind": "request unanswered",
                 "entry": "UPF logs the request but never answers",
                 "keys": {"nf": "upf"}, "citation": line}]

    episodes = EpisodeStore(_episodes_path(ctx))
    graph = build_graph(ctx["state_path"], ctx["records_dir"],
                        ctx["sandbox_root"],
                        log_runner=make_log_runner(windowed),
                        extractor=extract, episodes=episodes,
                        proposer=make_proposer(CANNED_PROPOSAL))
    run_to_approval(graph, event, stub)
    run_approval(build_graph(ctx["state_path"], ctx["records_dir"],
                             ctx["sandbox_root"], episodes=episodes,
                             proposer=make_proposer(CANNED_PROPOSAL)),
                 event["incident_id"], "approve", execute=False)
    stored = EpisodeStore(_episodes_path(ctx)).load()
    assert len(stored) == 1
    ep = stored[0]
    assert ep.decision == "approved-dry-run"
    # The correlated evidence keys become the episode's match keys.
    assert [(key.key, key.value) for key in ep.evidence_keys] == \
        [("nf", "upf")]


def test_without_episodes_seam_nothing_is_written(ctx, event, stub):
    run_to_approval(_graph(ctx), event, stub)
    run_approval(_graph(ctx), event["incident_id"], "approve", execute=False)
    assert not _episodes_path(ctx).exists()


# --- Episodic memory: the investigate node seeds the objective ---

UPF_LOG_LINE = ("upf     | 2025-06-15T15:05:01.510724553Z [open5gs-upf] INFO "
                "[upf] PFCP[0] Session Establishment Request "
                "(../src/upf/pfcp-sm.c:225)")


def _log_extractor(text, event):
    return [{"kind": "request unanswered",
             "entry": "UPF logs the request but never answers",
             "keys": {"nf": "upf"}, "citation": UPF_LOG_LINE}]


def _seeded_graph(ctx, episodes, search):
    windowed = (FIXTURES / "core_logs_n4_timeout.txt").read_text()
    return build_graph(ctx["state_path"], ctx["records_dir"],
                       ctx["sandbox_root"],
                       log_runner=make_log_runner(windowed),
                       extractor=_log_extractor,
                       episodes=episodes, search=search,
                       proposer=make_proposer(CANNED_PROPOSAL))


def test_investigate_seeds_objective_with_past_episodes(ctx, event, stub):
    episodes = EpisodeStore(_episodes_path(ctx))
    episodes.add(Episode(incident_id="inc-past",
                         procedure="n4_upf_timeout",
                         evidence_keys=[{"key": "nf", "value": "upf"}],
                         narrative="the UPF was stuck this way before",
                         action="restart_nf",
                         decision="approved-executed"))
    objectives = []

    def search(objective):
        objectives.append(objective)
        return {"narrative": "the UPF never answered",
                "cited_evidence": [{"citation": UPF_LOG_LINE}]}

    run_to_approval(_seeded_graph(ctx, episodes, search), event, stub)
    objective = objectives[0]
    assert "Past similar incidents retrieved from episodic memory" in objective
    assert "the UPF was stuck this way before" in objective
    assert "Explain the failure incident" in objective  # still the core task
    record = (ctx["records_dir"] / f'{event["incident_id"]}.md').read_text()
    assert "the UPF never answered" in record


def test_investigate_objective_untouched_without_episodes(ctx, event, stub):
    objectives = []

    def search(objective):
        objectives.append(objective)
        return {"narrative": "the UPF never answered",
                "cited_evidence": [{"citation": UPF_LOG_LINE}]}

    run_to_approval(_seeded_graph(ctx, None, search), event, stub)
    assert "Past similar incidents" not in objectives[0]


# --- Procedural memory: the propose node matches runbooks ---

# The log seam injects real evidence (keys nf=upf), so the runbook's
# symptom matching and the placeholder binding run against the inventory
# the propose node sees, not the stub's (which the specialists replace).
RUNBOOK = Runbook(
    slug="restart-stuck-upf",
    title="Restart a stuck UPF",
    procedure="n4_upf_timeout",
    symptoms=[EvidenceKey(key="nf", value="upf")],
    steps=["Confirm the UPF logged the request.",
           "Restart the upf service."],
    resolution={"action": "restart_nf", "args": {"nf": "{nf}"}})


def _propose_graph(ctx, runbooks=None, proposer=None):
    windowed = (FIXTURES / "core_logs_n4_timeout.txt").read_text()
    return build_graph(ctx["state_path"], ctx["records_dir"],
                       ctx["sandbox_root"],
                       log_runner=make_log_runner(windowed),
                       extractor=_log_extractor,
                       runbooks=runbooks,
                       proposer=proposer or make_proposer(CANNED_PROPOSAL))


def test_propose_prepends_matching_runbook_context(ctx, event, stub):
    calls = []

    def propose(incident, root_cause):
        calls.append(incident)
        return dict(CANNED_PROPOSAL)

    result = run_to_approval(
        _propose_graph(ctx, runbooks=[RUNBOOK], proposer=propose),
        event, stub)
    assert "Runbooks retrieved from procedural memory" in calls[0]
    assert "Restart a stuck UPF" in calls[0]
    assert event["description"] in calls[0]
    assert result["proposal"]["action"] == "restart_nf"


def test_propose_without_runbooks_incident_untouched(ctx, event, stub):
    calls = []

    def propose(incident, root_cause):
        calls.append(incident)
        return dict(CANNED_PROPOSAL)

    run_to_approval(_propose_graph(ctx, proposer=propose), event, stub)
    assert calls == [event["description"]]


def test_propose_binds_placeholder_args_and_hashes_the_bound_args(
        ctx, event, stub):
    def propose(incident, root_cause):
        return {"action": "restart_nf", "args": {"nf": "{nf}"},
                "justification": CANNED_PROPOSAL["justification"]}

    result = run_to_approval(_propose_graph(ctx, proposer=propose),
                             event, stub)
    proposal = result["proposal"]
    assert proposal["args"] == {"nf": "upf"}
    expected = {"action": "restart_nf", "args": {"nf": "upf"},
                "justification": CANNED_PROPOSAL["justification"]}
    assert proposal["hash"] == proposal_hash(expected)
    assert "restart upf" in "\n".join(proposal["commands"])


def test_propose_unbound_placeholder_yields_no_proposal(ctx, event, stub):
    def propose(incident, root_cause):
        return {"action": "restart_nf", "args": {"nf": "{missing}"},
                "justification": "j"}

    result = run_to_approval(_propose_graph(ctx, proposer=propose),
                             event, stub)
    assert result["proposal"] is None


def test_matching_runbook_does_not_change_the_hash(ctx, event, stub):
    # AC-3: the proposal hash still covers exactly the three fields, so a
    # matching runbook changes only the proposer's context, never the hash.
    other = dict(event, incident_id="inc-hash-compare")
    plain = run_to_approval(_propose_graph(ctx), event, stub)
    matched = run_to_approval(_propose_graph(ctx, runbooks=[RUNBOOK]),
                              other, stub)
    assert plain["proposal"]["hash"] == matched["proposal"]["hash"]
    assert plain["proposal"]["hash"] == proposal_hash(CANNED_PROPOSAL)
