"""Eval harness tests: the plane filter, offline with a stubbed search.

ADR-0002: run_eval.py itself is never executed here (every fixture run
costs Groq calls); these tests import the harness and stub run_lats plus
the judge, so no model call, download, or 5gcap subprocess happens.
"""

import json
from types import SimpleNamespace

from evals.run_eval import run_fixture
from triage.memory import Episode


def write_decode(tmp_path, name, obj):
    path = tmp_path / name
    path.write_text(json.dumps(obj), encoding="utf-8")
    return path


def two_plane_decodes(tmp_path):
    """An N2 decode with one failure (5GMM STATUS #91) and an SBI decode
    with one rejected NSSF procedure."""
    n2 = {"flows": [{
        "flow_id": 1, "partial": False,
        "messages": [{"ts": 1.0, "nas_inner": "5GMMStatus",
                      "nas_cause": {"code": 91,
                                    "name": "Payload was not forwarded"}}],
        "procedures": []}]}
    sbi = {"messages": [], "procedures": [
        {"kind": "Nnssf_NSSelection", "outcome": "reject", "status": 403}]}
    return {"n2": write_decode(tmp_path, "n2.json", n2),
            "sbi": write_decode(tmp_path, "sbi.json", sbi)}


def stub_search(seen):
    """run_lats stand-in: records the Incident it was handed, then
    completes with a fixed Episode."""
    def run_lats(capture, incident, store=None):
        seen.append(incident)
        return SimpleNamespace(
            episode=Episode.model_validate({
                "incident_type": "registration_reject",
                "narrative": "the stub's hypothesis",
                "cited_evidence": [{"message": "5GMMStatus", "cause": 91,
                                    "ts": 1.0}]}),
            reward=0.5, rollouts=2, trajectory=[["inspect flows", "x"]])
    return run_lats


def stub_judge(hypothesis, decoded):
    return {"scores": {"accuracy": 1.0, "specificity": 1.0,
                       "evidence": 1.0, "causality": 1.0}, "comment": ""}


def test_plane_filter_searches_only_own_plane(tmp_path, monkeypatch):
    paths = two_plane_decodes(tmp_path)

    seen = []
    monkeypatch.setattr("evals.run_eval.run_lats", stub_search(seen))
    results = run_fixture("auth_failure", paths, "auth_failure", 1,
                          stub_judge)
    assert [i["plane"] for i in seen] == ["n2"]
    assert results[0]["incident_types"] == ["registration_reject"]

    seen = []
    monkeypatch.setattr("evals.run_eval.run_lats", stub_search(seen))
    results = run_fixture("sbi_nssf_reject", paths, "sbi_nssf_reject", 1,
                          stub_judge)
    assert [i["plane"] for i in seen] == ["sbi"]
    assert results[0]["incident_types"] == ["registration_reject"]


def test_plane_filter_without_sbi_decode_stays_n2(tmp_path, monkeypatch):
    # an N2 fixture run before any SBI pcap exists: paths has no "sbi"
    paths = {"n2": two_plane_decodes(tmp_path)["n2"]}
    seen = []
    monkeypatch.setattr("evals.run_eval.run_lats", stub_search(seen))
    run_fixture("auth_failure", paths, "auth_failure", 1, stub_judge)
    assert [i["plane"] for i in seen] == ["n2"]
