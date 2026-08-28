"""The root-cause investigation: a LATS-style search at the Dispatcher
layer over the multi-source evidence inventory.

triage's Tree and signatures are imported as a library — dispatch is the
only context depending on triage's Python API; the expand signature is
subclassed so its prompt describes the Dispatcher's action space — while
the execute step is the Dispatcher's own: `inspect` renders the
correlated inventory and `finalize` accepts an episode whose citations
must name inventory items exactly, extending the grounding discipline
across pcap, log and KPI. The winning trajectory's narrative becomes the
record's root-cause section. The search is the stub seam: tests inject a
canned search or a real Tree with stub expand/evaluate steps (the spec's
stub-injected Tree pattern); the live search's Groq predictors are never
built in pytest (ADR-0002)."""

import json
from types import SimpleNamespace

import pytest

import triage.search as triage_search
from test_log import EVENT, UPF_LINE

import dispatch.root_cause as root_cause_mod
from dispatch.root_cause import (grounded_episode, inspect_observation,
                                 make_execute, objective_text,
                                 run_root_cause)
# The live default, bound before the conftest blanket stubs the module
# attribute — tests of the lazy construction reach the real function.
from dispatch.root_cause import default_search as live_default_search

# The post-specialist inventory: one grounded item per source, pcap and
# log correlated via nf=upf.
EVIDENCE = [
    {"source": "pcap", "kind": "N4 session establishment request unanswered",
     "ts": 1749999950.0,
     "entry": "PFCP Session Establishment Request (Sx) to UPF with no "
              "response by capture end",
     "cause": None, "endpoints": ["10.53.0.11:8805", "10.53.0.13:8805"],
     "keys": {"teid": "0x12345678", "nf": "upf"}, "citation": "n4:1"},
    {"source": "log", "kind": "request unanswered",
     "ts": 1749999901.510724,
     "entry": "UPF logs the request but never answers",
     "cause": None, "endpoints": None, "keys": {"nf": "upf"},
     "citation": UPF_LINE},
    {"source": "kpi", "kind": "KPI deviation",
     "ts": 1749999960.0,
     "entry": "procedure_success_rate degraded to 0.8",
     "cause": None, "endpoints": None, "keys": {"flow_id": 1},
     "citation": "kpi.procedure_success_rate=0.8"},
]
LINKS = [{"a": 0, "b": 1, "key": "nf", "value": "upf"}]

NARRATIVE = ("The UPF logged the PFCP Session Establishment Request but "
             "never answered it, and procedure_success_rate degraded to "
             "0.8: the UPF is stuck.")
EPISODE = {"narrative": NARRATIVE,
           "cited_evidence": [{"citation": "n4:1"},
                              {"citation": UPF_LINE},
                              {"citation": "kpi.procedure_success_rate=0.8"}]}


def _finalize_arg(episode):
    return f"finalize {json.dumps(episode)}"


# --- AC-1: triage's Tree and signatures imported as a library ---

def test_imports_triages_tree_and_signatures():
    assert root_cause_mod.Tree is triage_search.Tree
    # The expand signature is imported as a library and subclassed so its
    # prompt describes the Dispatcher's action space, not triage's decode
    # tools; triage's class itself is never mutated (ADR-0001).
    assert issubclass(root_cause_mod.ExpandSignature,
                      triage_search.ExpandSignature)
    assert root_cause_mod.EvaluateSignature is triage_search.EvaluateSignature
    assert root_cause_mod.parse_action is triage_search.parse_action


def test_expand_signature_prompt_describes_dispatcher_tools():
    # The subclassed expand signature names the Dispatcher's tools and
    # citation schema — never triage's decode tools, which the execute
    # step would reject.
    prompt = root_cause_mod.ExpandSignature.__doc__
    assert "inspect" in prompt
    assert "finalize" in prompt
    assert "citation" in prompt
    assert "topology" not in prompt
    assert "spec <question>" not in prompt
    assert "memory" not in prompt


# --- the search objective: correlated evidence from all three sources ---

def test_objective_names_correlated_evidence_from_all_sources():
    text = objective_text(EVENT, EVIDENCE, LINKS)
    assert EVENT["description"] in text
    assert "n4:1" in text                              # pcap
    assert UPF_LINE in text                            # log
    assert "kpi.procedure_success_rate=0.8" in text    # kpi
    assert "nf=upf" in text                            # the correlation link
    assert "finalize" in text                          # the search objective


def test_inspect_observation_lists_inventory_and_links():
    text = inspect_observation(EVIDENCE, LINKS)
    assert "[1] pcap" in text and "citation: n4:1" in text
    assert "[2] log" in text
    assert "[3] kpi" in text
    assert "[1] ↔ [2] via nf=upf" in text


def test_inspect_observation_without_links():
    assert "no links" in inspect_observation(EVIDENCE, [])


# --- the finalize tool: the shared grounder ---

def test_finalize_accepts_fully_grounded_episode():
    obs, episode = make_execute(EVIDENCE, LINKS)(_finalize_arg(EPISODE))
    assert obs == "finalize accepted: hypothesis grounded in 3 evidence item(s)."
    assert episode == {"narrative": NARRATIVE,
                       "cited_evidence": [{"citation": "n4:1"},
                                          {"citation": UPF_LINE},
                                          {"citation": "kpi.procedure_success_rate=0.8"}]}


def test_finalize_filters_ungrounded_citations():
    # One fabricated citation is dropped; the grounded two stand.
    episode = {"narrative": NARRATIVE,
               "cited_evidence": [{"citation": "n4:1"},
                                  {"citation": "the upf exploded"},
                                  {"citation": "kpi.procedure_success_rate=0.8"}]}
    obs, grounded = make_execute(EVIDENCE, LINKS)(_finalize_arg(episode))
    assert obs == "finalize accepted: hypothesis grounded in 2 evidence item(s)."
    assert [c["citation"] for c in grounded["cited_evidence"]] == \
        ["n4:1", "kpi.procedure_success_rate=0.8"]


def test_finalize_rejects_episode_with_no_grounded_citations():
    episode = {"narrative": NARRATIVE,
               "cited_evidence": [{"citation": "invented"}]}
    obs, grounded = make_execute(EVIDENCE, LINKS)(_finalize_arg(episode))
    assert grounded is None
    assert "finalize rejected" in obs


def test_finalize_rejects_malformed_json():
    obs, episode = make_execute(EVIDENCE, LINKS)("finalize not json")
    assert episode is None
    assert "not valid JSON" in obs


def test_finalize_rejects_non_episode_json():
    obs, episode = make_execute(EVIDENCE, LINKS)('finalize ["a list"]')
    assert episode is None
    assert "finalize rejected" in obs


def test_execute_rejects_unknown_action():
    obs, episode = make_execute(EVIDENCE, LINKS)("topology")
    assert episode is None
    assert "unknown action" in obs


def test_grounded_episode_rejects_missing_narrative():
    episode = {"cited_evidence": [{"citation": "n4:1"}]}
    assert grounded_episode(episode, EVIDENCE) is None


# --- the run_root_cause seam ---

def test_run_root_cause_returns_winning_narrative():
    def search(objective):
        # The objective names the correlated evidence from all sources.
        assert "n4:1" in objective
        assert UPF_LINE in objective
        assert "kpi.procedure_success_rate=0.8" in objective
        return EPISODE

    assert run_root_cause(EVENT, EVIDENCE, LINKS, search=search) == NARRATIVE


def test_run_root_cause_rejects_ungrounded_episode():
    # The node re-grounds the search's episode, so an injected fake is
    # verified the same way as the live path — never a hallucinated cite.
    def search(objective):
        return {"narrative": NARRATIVE,
                "cited_evidence": [{"citation": "invented"}]}

    assert run_root_cause(EVENT, EVIDENCE, LINKS, search=search) == ""


def test_run_root_cause_search_failure_degrades():
    def boom(objective):
        raise RuntimeError("GROQ_API_KEY is not set")

    assert run_root_cause(EVENT, EVIDENCE, LINKS, search=boom) == ""


def test_run_root_cause_without_evidence_never_searches():
    calls = []

    def search(objective):
        calls.append(objective)

    assert run_root_cause(EVENT, [], [], search=search) == ""
    assert calls == []


def test_default_search_builds_lazily_and_requires_groq_key(monkeypatch):
    # The live default: construction is key-free (the Groq predictors
    # build on first use); a search without GROQ_API_KEY raises the
    # ADR-0002 RuntimeError, never touching the network.
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    search = live_default_search(EVIDENCE, LINKS)
    assert callable(search)
    with pytest.raises(RuntimeError, match="GROQ_API_KEY"):
        search("objective")


def test_run_root_cause_with_stub_injected_tree():
    # The spec's stub-injected Tree pattern: the real triage Tree with
    # canned expand/evaluate steps and the Dispatcher's execute — the
    # MCTS machinery runs in pytest without Groq (ADR-0002).
    def expand(objective, trajectory, n):
        return [_finalize_arg(EPISODE)]

    def evaluate(objective, trajectory):
        return SimpleNamespace(reward=1.0, status="complete",
                               reflection="grounded")

    tree = root_cause_mod.Tree(expand=expand, evaluate=evaluate,
                               execute=make_execute(EVIDENCE, LINKS))
    result = run_root_cause(EVENT, EVIDENCE, LINKS,
                            search=lambda objective: tree.run(objective).episode)
    assert result == NARRATIVE
