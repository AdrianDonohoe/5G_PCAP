"""LATS search mechanics tests: deterministic tool dispatch, the
finalize/grounding completeness bar, and the MCTS tree — all against stub
expand/evaluate callables.

Per ADR-0002 the suite stays cheap: no Groq call and no dspy.Predict here;
the gpt-oss:120b wiring is exercised by an ad-hoc acceptance pass, not the
suite. Default expand/evaluate only build their dspy predictors lazily, so
importing triage.search never requires GROQ_API_KEY.
"""

import json

import pytest

from triage.evidence import DecodedCapture
from triage.memory import MemoryStore
from triage.search import (Tree, execute_action, memory_context,
                           objective_text, parse_action, run_lats)


def mini_capture():
    return DecodedCapture(n2={
        "kpis": {"procedure_failures": 1},
        "flows": [{
            "flow_id": 1, "ran_ue_ngap_id": 1, "amf_ue_ngap_id": 1,
            "partial": False,
            "messages": [
                {"ts": 1000.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                 "ngap": "InitialUEMessage", "kind": "initiatingMessage",
                 "nas": "5GMMRegistrationRequest", "nas_protected": False,
                 "nas_inner": None, "nas_cause": None, "unparsed": None},
                {"ts": 1001.5, "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1",
                 "ngap": "DownlinkNASTransport", "kind": "initiatingMessage",
                 "nas": "5GMMSecProtNASMessage", "nas_protected": True,
                 "nas_inner": "5GMMStatus",
                 "nas_cause": {"code": 91,
                               "name": "Payload was not forwarded"},
                 "unparsed": None},
            ],
            "procedures": [{
                "kind": "registration", "start_ts": 1000.0,
                "end_ts": 1001.5,
                "start_msg": "5GMMRegistrationRequest",
                "end_msg": "5GMMStatus", "outcome": "reject",
                "duration_ms": 1500.0}]}],
        "unassociated": []})


def episode_json(**evidence):
    """A grounded Episode citing the mini capture's 5GMMStatus #91."""
    episode = {"incident_type": "registration_reject",
               "narrative": "The AMF echoed back cause 91: the payload was "
                            "not forwarded.",
               "cited_evidence": [
                   {"message": "5GMMStatus", "cause": 91, "ts": 1001.5,
                    **evidence}]}
    return json.dumps(episode)


class StubSpecIndex:
    def __init__(self, chunks=None):
        self.chunks = chunks or [
            {"spec": "24501", "text": "DNN not supported in the slice"}]

    def search(self, query, top_k=5):
        return [(c, 0.9) for c in self.chunks][:top_k]


def eval_stub(objective, trajectory):
    if "finalize accepted" in trajectory:
        return {"reward": 0.9, "status": "complete",
                "reflection": "grounded"}
    if "spec cause 91" in trajectory:
        return {"reward": 0.0, "status": "failed",
                "reflection": "irrelevant"}
    return {"reward": 0.5, "status": "incomplete",
            "reflection": "partial"}


def scripted_expand():
    """Probe with two tool actions, then finalize once a flow is seen
    (the flow detail observation starts with "Flow 1 (...")."""
    def expand(objective, trajectory, n):
        if "Flow 1" in trajectory:
            return [f"finalize {episode_json()}"]
        return ["inspect flow:1", "spec cause 91"]
    return expand


# --- action parsing ---

def test_parse_action():
    assert parse_action("inspect flow:1") == ("inspect", "flow:1")
    assert parse_action('spec "cause 91 DNN"') == ("spec", "cause 91 DNN")
    assert parse_action("topology") == ("topology", "")
    assert parse_action("memory incident_type=auth_failure") == \
        ("memory", "incident_type=auth_failure")
    assert parse_action("inspect:flow:1:2") == ("inspect", "flow:1:2")
    assert parse_action("FINALIZE {}") == ("finalize", "{}")
    assert parse_action("") == ("", "")


# --- execute: deterministic tool dispatch ---

def test_execute_inspect():
    observation, episode = execute_action(mini_capture(), "inspect flows")
    assert observation.startswith("Capture flows (1):")
    assert episode is None


def test_execute_topology():
    observation, _ = execute_action(mini_capture(), "topology")
    assert observation.startswith("Topology (inferred from message content")
    assert "gNB" in observation and "10.0.0.1" in observation


def test_execute_spec_with_stub_index():
    observation, _ = execute_action(mini_capture(), "spec cause 91",
                                    spec_index=StubSpecIndex())
    assert '3GPP spec retrieval for "cause 91"' in observation
    assert "DNN not supported in the slice" in observation


def test_execute_memory(tmp_path):
    store = MemoryStore(tmp_path / "episodes.jsonl")
    store.add({"incident_type": "auth_failure",
               "narrative": "wrong long-term key",
               "cited_evidence": [
                   {"message": "5GMMAuthenticationFailure", "cause": 21}]})
    observation, _ = execute_action(mini_capture(),
                                    "memory incident_type=auth_failure",
                                    store=store)
    assert "wrong long-term key" in observation


def test_execute_unknown_action():
    observation, _ = execute_action(mini_capture(), "frobnicate everything")
    assert 'unknown action "frobnicate everything"' in observation


# --- finalize: the completeness bar, enforced in code ---

def test_finalize_accepted_when_grounded():
    observation, episode = execute_action(
        mini_capture(), f"finalize {episode_json()}")
    assert observation.startswith("finalize accepted")
    assert "grounded in 1 evidence item(s)" in observation
    assert episode is not None and episode.incident_type == \
        "registration_reject"


def test_finalize_rejects_invalid_json():
    observation, episode = execute_action(mini_capture(),
                                          "finalize {not json}")
    assert "finalize rejected" in observation
    assert "not a valid Episode" in observation
    assert episode is None


def test_finalize_rejects_bad_incident_type():
    bad = json.dumps({"incident_type": "handover_failure",
                      "narrative": "x",
                      "cited_evidence": [{"message": "5GMMStatus"}]})
    observation, episode = execute_action(mini_capture(), f"finalize {bad}")
    assert "finalize rejected" in observation
    assert episode is None


def test_finalize_rejects_empty_narrative_and_no_evidence():
    for bad in [json.dumps({"incident_type": "registration_reject",
                            "narrative": "",
                            "cited_evidence": [
                                {"message": "5GMMStatus", "ts": 1001.5}]}),
                json.dumps({"incident_type": "registration_reject",
                            "narrative": "x", "cited_evidence": []})]:
        observation, episode = execute_action(mini_capture(),
                                              f"finalize {bad}")
        assert "finalize rejected" in observation
        assert episode is None


def test_finalize_rejects_ungrounded_evidence():
    for bad in [episode_json(ts=999.9),          # no such timestamp
                episode_json(message="PDUSessionReject"),  # no such message
                episode_json(cause=42)]:         # wrong cause for the ts
        observation, episode = execute_action(mini_capture(),
                                              f"finalize {bad}")
        assert "no cited evidence matches a decoded message" in observation
        assert episode is None


def test_finalize_rejects_evidence_without_ts():
    bad = json.dumps({"incident_type": "registration_reject",
                      "narrative": "x",
                      "cited_evidence": [{"message": "5GMMStatus",
                                          "cause": 91}]})
    observation, episode = execute_action(mini_capture(), f"finalize {bad}")
    assert "no cited evidence matches" in observation
    assert episode is None


def test_finalize_ts_tolerance_covers_displayed_precision():
    # observations print ts to 3 decimals; the decode keeps full precision
    capture = mini_capture()
    capture.n2["flows"][0]["messages"][1]["ts"] = 1001.500876
    observation, episode = execute_action(
        capture, f"finalize {episode_json(ts=1001.501)}")
    assert "finalize accepted" in observation
    assert episode is not None


def test_finalize_accepts_ngap_name_citation():
    observation, episode = execute_action(
        mini_capture(),
        "finalize " + json.dumps({
            "incident_type": "registration_reject",
            "narrative": "registration never completed",
            "cited_evidence": [{"message": "InitialUEMessage",
                                "ts": 1000.0}]}))
    assert "finalize accepted" in observation
    assert episode is not None


# --- the MCTS tree with stubs ---

def test_tree_finds_completed_hypothesis():
    tree = Tree(scripted_expand(), eval_stub,
                execute=lambda action: execute_action(mini_capture(), action,
                                                      spec_index=StubSpecIndex()))
    result = tree.run("explain the failure", n_branches=2)
    assert result.episode is not None
    assert result.episode.incident_type == "registration_reject"
    assert result.reward == pytest.approx(0.9)
    assert result.trajectory[0][0] == "inspect flow:1"
    assert result.trajectory[-1][0].startswith("finalize")
    assert "finalize accepted" in result.trajectory[-1][1]


def test_tree_expand_receives_trajectory():
    seen = []

    def expand(objective, trajectory, n):
        seen.append(trajectory)
        return scripted_expand()(objective, trajectory, n)

    tree = Tree(expand, eval_stub,
                execute=lambda action: execute_action(mini_capture(), action,
                                                      spec_index=StubSpecIndex()))
    tree.run("explain", n_branches=2)
    assert any("action: inspect flow:1" in t and "observation:" in t
               for t in seen)


def test_failed_nodes_are_pruned_by_ucb():
    # the spec branch scores 0/failed; UCB must route into the inspect
    # branch, whose finalize completes
    result = run_lats(mini_capture(),
                      {"flow_id": 1, "procedure": "registration"},
                      expand=scripted_expand(), evaluate=eval_stub,
                      spec_index=StubSpecIndex())
    assert result.episode is not None
    assert result.trajectory[0][0] == "inspect flow:1"


def test_search_exhausts_rollouts_without_finalize():
    def never_finalize(objective, trajectory, n):
        return ["inspect flows"]

    def incomplete(objective, trajectory):
        return {"reward": 0.5, "status": "incomplete", "reflection": ""}

    result = run_lats(mini_capture(),
                      {"flow_id": 1, "procedure": "registration"},
                      expand=never_finalize, evaluate=incomplete,
                      max_rollouts=3)
    assert result.episode is None
    assert result.rollouts == 3


def test_expand_failure_degrades():
    def boom(objective, trajectory, n):
        raise RuntimeError("llm down")

    result = run_lats(mini_capture(),
                      {"flow_id": 1, "procedure": "registration"},
                      expand=boom, evaluate=eval_stub, max_rollouts=3)
    assert result.episode is None
    assert result.rollouts == 3  # search survived, no crash


def test_evaluate_failure_degrades():
    def boom(objective, trajectory):
        raise RuntimeError("llm down")

    # a stub index: without one, "spec cause 91" would fall through to the
    # production SpecIndex and (on a stale cache) start a full corpus
    # embed — ADR-0002's suite must never cost that.
    result = run_lats(mini_capture(),
                      {"flow_id": 1, "procedure": "registration"},
                      expand=scripted_expand(), evaluate=boom,
                      spec_index=StubSpecIndex())
    assert result.episode is None  # every node failed, search survived


def test_objective_text():
    text = objective_text({"flow_id": 3, "procedure": "PDU Session",
                           "shape": "partial flow (timeout)"})
    assert "PDU Session procedure failed for flow 3" in text
    assert "partial flow (timeout)" in text
    assert "Past similar incidents" not in text  # no memory: unchanged
    for incident_type in ("auth_failure", "registration_reject",
                          "registration_timeout",
                          "pdu_session_reject_slice",
                          "pdu_session_reject_other",
                          "pdu_session_timeout",
                          "sbi_udm_timeout", "sbi_nssf_reject"):
        assert incident_type in text


def test_objective_text_sbi_incident():
    text = objective_text({"plane": "sbi", "flow_id": None,
                           "procedure": "Nudm_UEAuthentication",
                           "shape": "no terminal message (timeout)"})
    assert "Nudm_UEAuthentication procedure failed" in text
    assert "on the SBI plane" in text
    assert "flow None" not in text
    assert "sbi[:<i>]" in text  # the handle space lists the SBI handles
    assert "There is no reject message" in text  # timeout special-case fires


def test_objective_text_includes_memory_context():
    text = objective_text({"flow_id": 3, "procedure": "PDU Session"},
                          memory="Past similar incidents: [1] auth_failure")
    assert "Past similar incidents" in text
    assert "context only" in text  # memory is context, not evidence


def test_memory_context_ranks_relevant_episodes(tmp_path):
    store = MemoryStore(tmp_path / "episodes.jsonl")
    store.add({"incident_type": "auth_failure",
               "narrative": "synch failure took down a past registration",
               "cited_evidence": [{"message": "5GMMStatus", "cause": 91,
                                   "ts": 999.0}]})
    store.add({"incident_type": "pdu_session_reject_other",
               "narrative": "unrelated PDU session failure",
               "cited_evidence": [{"message": "5GSMPDUSessionEstabRequest",
                                   "cause": 67, "ts": 500.0}]})
    flow = mini_capture().n2["flows"][0]
    text = memory_context(store, {"flow_id": 1,
                                  "procedure": "Registration"}, flow)
    assert "synch failure took down a past registration" in text
    assert "unrelated PDU session failure" not in text


def test_memory_context_empty_store(tmp_path):
    flow = mini_capture().n2["flows"][0]
    assert memory_context(MemoryStore(tmp_path / "none.jsonl"),
                          {"flow_id": 1, "procedure": "Registration"},
                          flow) == ""


def sbi_capture():
    return DecodedCapture(n2={}, sbi={
        "messages": [{
            "ts": 1000.0, "src_ip": "10.0.0.3", "dst_ip": "10.0.0.4",
            "src_port": 50001, "dst_port": 7777, "stream_id": 1,
            "direction": "request", "method": "GET",
            "path": "/nnssf-nsselection/v1/network-slice-information",
            "status": None, "body_len": 0, "service": "Nnssf_NSSelection",
            "name": "Nnssf_NSSelection", "problem_title": None,
            "problem_cause": None, "unparsed": None},
            {"ts": 1000.5, "src_ip": "10.0.0.4", "dst_ip": "10.0.0.3",
             "src_port": 7777, "dst_port": 50001, "stream_id": 1,
             "direction": "response", "method": None, "path": None,
             "status": 403, "body_len": 57, "service": "Nnssf_NSSelection",
             "name": "Nnssf_NSSelection",
             "problem_title": "Cannot find NSI",
             "problem_cause": "SNSSAI_NOT_SUPPORTED", "unparsed": None}],
        "procedures": [], "unpaired_requests": 0})


def test_sbi_evidence_grounds():
    # cited (service name, ts) matches an SBI message; cause is null
    episode = json.dumps({
        "incident_type": "sbi_nssf_reject",
        "narrative": "the NSSF rejected the slice consult with 403",
        "cited_evidence": [{"message": "Nnssf_NSSelection", "cause": None,
                            "ts": 1000.5}]})
    observation, ep = execute_action(sbi_capture(), f"finalize {episode}")
    assert "finalize accepted" in observation
    assert ep.incident_type == "sbi_nssf_reject"


def test_sbi_evidence_ungrounded_without_sbi_loaded():
    episode = json.dumps({
        "incident_type": "sbi_nssf_reject",
        "narrative": "x",
        "cited_evidence": [{"message": "Nnssf_NSSelection", "cause": None,
                            "ts": 1000.5}]})
    observation, ep = execute_action(mini_capture(), f"finalize {episode}")
    assert "no cited evidence matches a decoded message" in observation
    assert ep is None


def test_memory_context_sbi_incident(tmp_path):
    # flow_id None -> no N2 flow to mine; the procedure itself is the
    # service, and sbi_nssf_reject maps onto "PDU Session" episodes
    store = MemoryStore(tmp_path / "episodes.jsonl")
    store.add({"incident_type": "sbi_nssf_reject",
               "narrative": "NSSF 403 on a past run",
               "cited_evidence": [{"message": "Nnssf_NSSelection",
                                   "ts": 999.0}]})
    text = memory_context(store, {"plane": "sbi", "flow_id": None,
                                  "procedure": "PDU Session"}, None)
    assert "NSSF 403 on a past run" in text


def test_run_lats_seeds_objective_with_memory(tmp_path):
    store = MemoryStore(tmp_path / "episodes.jsonl")
    store.add({"incident_type": "auth_failure",
               "narrative": "a past registration died the same way",
               "cited_evidence": [{"message": "5GMMStatus", "cause": 91,
                                   "ts": 999.0}]})
    seen = []

    def capture_objective(objective, trajectory, n):
        seen.append(objective)
        return ["inspect flows"]

    run_lats(mini_capture(),
             {"flow_id": 1, "procedure": "registration"},
             store=store, expand=capture_objective, evaluate=eval_stub,
             max_rollouts=1)
    assert any("Past similar incidents" in objective for objective in seen)
    assert any("a past registration died the same way" in objective
               for objective in seen)
