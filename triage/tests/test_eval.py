"""Eval harness tests: the plane filter and the merged decode path, offline
with a stubbed search.

ADR-0002: run_eval.py itself is never executed here (every fixture run
costs Groq calls); these tests import the harness and stub run_lats plus
the judge, so no model call or download happens. The one exception is the
merged-invocation test, which shells 5gcap's decode (offline) to prove the
three-plane export loads with correlated flow ids.
"""

import json
from pathlib import Path
from types import SimpleNamespace

from evals.run_eval import decode_fixture, run_fixture
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


def three_plane_decodes(tmp_path):
    """N2 + SBI decodes (as above) plus an N4 decode with one
    session-establishment timeout."""
    paths = two_plane_decodes(tmp_path)
    n4 = {"messages": [], "procedures": [
        {"kind": "session_establishment", "outcome": "timeout"}]}
    paths["n4"] = write_decode(tmp_path, "n4.json", n4)
    return paths


def test_plane_filter_n4_searches_only_n4(tmp_path, monkeypatch):
    paths = three_plane_decodes(tmp_path)
    seen = []
    monkeypatch.setattr("evals.run_eval.run_lats", stub_search(seen))
    results = run_fixture("n4_upf_timeout", paths, "n4_upf_timeout", 1,
                          stub_judge)
    assert [i["plane"] for i in seen] == ["n4"]
    assert results[0]["incident_types"] == ["registration_reject"]


def merged_failure_decode(tmp_path):
    """A merged export with a joined failure per plane: N2 flow 1's
    partial flow, an N4 establishment timeout joined to flow 1, an SBI
    reject joined to flow 1, and an unjoined SBI timeout."""
    merged = {
        "kpis": {}, "unassociated": [],
        "flows": [{
            "flow_id": 1, "partial": True,
            "messages": [{"ts": 1.0, "ngap": "InitialUEMessage",
                          "nas": "5GMMRegistrationRequest"}],
            "procedures": [],
            "n4_refs": [0], "sbi_refs": [0]}],
        "n4": {
            "messages": [{"ts": 2.0, "name": "PFCP Session Establishment "
                                          "Request", "seq": 1,
                          "seid": None, "cause": None, "flow_id": 1}],
            "procedures": [{"kind": "session_establishment",
                            "outcome": "timeout", "flow_id": 1}],
            "unpaired_requests": 1},
        "sbi": {
            "messages": [],
            "procedures": [
                {"kind": "Nnssf_NSSelection", "outcome": "reject",
                 "status": 403, "flow_id": 1},
                {"kind": "Nudm_UEAuthentication", "outcome": "timeout",
                 "flow_id": None}],
            "unpaired_requests": 0}}
    return {"n2": write_decode(tmp_path, "merged.json", merged)}


def test_merged_fixture_searches_every_plane(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr("evals.run_eval.run_lats", stub_search(seen))
    results = run_fixture("sandbox", merged_failure_decode(tmp_path),
                          "n4_upf_timeout", 1, stub_judge)
    # every plane's incidents reach the search; the joined plane
    # incidents carry their correlated flow id, the unjoined one None
    assert [(i["plane"], i["flow_id"], i["procedure"]) for i in seen] == [
        ("n2", 1, "Registration"),
        ("n4", 1, "session_establishment"),
        ("sbi", 1, "Nnssf_NSSelection"),
        ("sbi", None, "Nudm_UEAuthentication")]
    assert results[0]["incident_types"] == ["registration_reject"] * 4


def test_decode_fixture_merged_invocation(tmp_path):
    # the merged branch: ONE 5gcap invocation over the sandbox triple
    # produces a single merged export whose plane sections carry the
    # correlated flow ids and the cross-plane KPIs
    paths = decode_fixture("sandbox", tmp_path)
    assert set(paths) == {"n2"}
    data = json.loads(Path(paths["n2"]).read_text())
    assert "sbi" in data and "n4" in data
    assert sorted(f for f in {m.get("flow_id")
                              for m in data["n4"]["messages"]}
                  if f is not None) == [1, 2, 3]
    assert sorted(f for f in {p.get("flow_id")
                              for p in data["sbi"]["procedures"]}
                  if f is not None) == [1, 2, 3]
    assert data["kpis"]["sbi_to_n4_ms"] is not None
