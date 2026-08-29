"""The Proposal node: the LLM selects a remediation from the fixed
five-action vocabulary and drafts the justification, under ADR-0002's
guard rails. Code enforces the vocabulary and the args shape and keeps
only the three fields the Executor renders — anything else the LLM adds
(commands, hashes) is dropped, so the recorded commands are always
template-rendered, never LLM text. An invalid selection yields no
proposal. The proposer is the stub seam; the live default's Groq
predictor is never built in pytest."""

import pytest

from _helpers import make_proposer

import dispatch.proposal as proposal_mod
from dispatch.proposal import run_proposal
# The live default, bound before the conftest blanket stubs the module
# attribute — tests of the lazy construction reach the real function.
from dispatch.proposal import default_propose as live_default_propose

EVENT = {"description": "UE1's PDU session establishment hangs."}
ROOT_CAUSE = "The UPF logged the request and never answered it."

# One valid (action, args) pair per vocabulary entry. Arg values are
# checked against the sandbox allowlists later, at the Executor render
# rail in the propose node.
VALID_SELECTIONS = [
    ("restart_nf", {"nf": "upf"}),
    ("revert_config", {"path": "core/config/upf.yaml"}),
    ("reseed_subscriber", {"imsi": "999700000000001"}),
    ("rerun_capture", {"scenario": "n4_upf_timeout"}),
    ("observe_only", {}),
]


@pytest.mark.parametrize("action,args", VALID_SELECTIONS)
def test_each_vocabulary_action_is_accepted(action, args):
    justification = "because it addresses the root cause"
    selection = {"action": action, "args": args,
                 "justification": justification}
    assert run_proposal(EVENT, ROOT_CAUSE,
                        proposer=make_proposer(selection)) \
        == {"action": action, "args": args, "justification": justification}


def test_llm_extra_fields_are_dropped():
    # AC-2: commands come from deterministic templates, never LLM text —
    # a selection smuggling extra fields is reduced to the three the
    # Executor renders.
    selection = {"action": "restart_nf", "args": {"nf": "upf"},
                 "justification": "clears the stuck state",
                 "commands": ["rm -rf /"], "hash": "fake",
                 "approved": True}
    assert run_proposal(EVENT, ROOT_CAUSE,
                        proposer=make_proposer(selection)) \
        == {"action": "restart_nf", "args": {"nf": "upf"},
            "justification": "clears the stuck state"}


def test_action_outside_vocabulary_yields_no_proposal():
    # AC-1: the fixed five-action vocabulary — anything else is rejected.
    selection = {"action": "reboot_the_lab", "args": {},
                 "justification": "whatever"}
    assert run_proposal(EVENT, ROOT_CAUSE,
                        proposer=make_proposer(selection)) is None


@pytest.mark.parametrize("selection", [
    {"action": "restart_nf", "justification": "j"},            # no args
    {"action": "restart_nf", "args": "upf", "justification": "j"},
    {"action": "restart_nf", "args": {}, "justification": ""},  # empty
    {"action": "restart_nf", "args": {}, "justification": 7},
    {"action": "restart_nf", "args": {}},                      # missing
    {"args": {}, "justification": "j"},                        # no action
    # observe_only takes no args — the render rail skips it, so the
    # vocabulary check must reject bogus args here.
    {"action": "observe_only", "args": {"nf": "hax"},
     "justification": "j"},
    ["a list"],                                                # not a dict
    "a string",
])
def test_malformed_selections_yield_no_proposal(selection):
    assert run_proposal(EVENT, ROOT_CAUSE,
                        proposer=make_proposer(selection)) is None


def test_proposer_failure_yields_no_proposal():
    def boom(incident, root_cause):
        raise RuntimeError("GROQ_API_KEY is not set")

    assert run_proposal(EVENT, ROOT_CAUSE, proposer=boom) is None


def test_proposer_receives_incident_and_root_cause():
    calls = []

    def propose(incident, root_cause):
        calls.append((incident, root_cause))
        return {"action": "observe_only", "args": {},
                "justification": "watch and re-run the capture later"}

    assert run_proposal(EVENT, ROOT_CAUSE, proposer=propose)["action"] \
        == "observe_only"
    assert calls == [(EVENT["description"], ROOT_CAUSE)]


def test_run_proposal_without_a_proposer_degrades_under_the_blanket():
    # The conftest blanket stubs the live default; run_proposal degrades
    # to no proposal rather than building a Groq predictor (ADR-0002).
    assert run_proposal(EVENT, ROOT_CAUSE) is None


def test_default_propose_builds_lazily_and_requires_groq_key(monkeypatch):
    # The live default: construction is key-free (the Groq predictor
    # builds on first use); a proposal without GROQ_API_KEY raises the
    # ADR-0002 RuntimeError, never touching the network.
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    propose = live_default_propose()
    assert callable(propose)
    with pytest.raises(RuntimeError, match="GROQ_API_KEY"):
        propose(EVENT["description"], ROOT_CAUSE)
