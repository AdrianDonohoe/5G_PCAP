"""Episodic memory store + query_episodic_memory tests (tmp_path stores).

Per ADR-0002 the suite stays cheap: these tests exercise the local JSON
store and the structured-lookup logic only — no models, no network.
"""

import pytest
from pydantic import ValidationError

from triage.memory import (CitedEvidence, Episode, MemoryStore, consolidate,
                           query_episodic_memory)


def make_store(tmp_path):
    return MemoryStore(tmp_path / "episodes.jsonl")


EP = {
    "incident_type": "auth_failure",
    "narrative": "gNB sent AUTHENTICATION FAILURE after the UDM rejected "
                 "the SUCI: wrong long-term key, not a radio problem.",
    "cited_evidence": [
        {"message": "5GMMAuthenticationFailure", "cause": 21, "ts": 1.0},
    ],
}


def test_add_load_roundtrip(tmp_path):
    store = make_store(tmp_path)
    episode = store.add(EP)
    assert isinstance(episode, Episode)
    assert store.load() == [episode]


def test_add_accepts_episode_instance(tmp_path):
    store = make_store(tmp_path)
    episode = Episode(**EP)
    assert store.add(episode) is episode
    assert store.load() == [episode]


def test_rejects_invalid_episodes(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(ValidationError):
        store.add({**EP, "incident_type": "handover_failure"})
    with pytest.raises(ValidationError):
        store.add({**EP, "narrative": ""})
    with pytest.raises(ValidationError):
        store.add({**EP, "cited_evidence": []})
    assert store.load() == []


def test_accepts_sbi_incident_types(tmp_path):
    store = make_store(tmp_path)
    store.add({**EP, "incident_type": "sbi_udm_timeout",
               "cited_evidence": [{"message": "Nudm_UEAuthentication",
                                   "cause": None, "ts": 1.0}]})
    store.add({**EP, "incident_type": "sbi_nssf_reject",
               "cited_evidence": [{"message": "Nnssf_NSSelection",
                                   "cause": None, "ts": 1.0}]})
    assert [ep.incident_type for ep in store.load()] == \
        ["sbi_udm_timeout", "sbi_nssf_reject"]


def test_accepts_n4_incident_types(tmp_path):
    store = make_store(tmp_path)
    store.add({**EP, "incident_type": "n4_upf_timeout",
               "cited_evidence": [{"message": "PFCP Session Establishment Request",
                                   "cause": None, "ts": 1.0}]})
    assert [ep.incident_type for ep in store.load()] == ["n4_upf_timeout"]


def test_appends_across_instances(tmp_path):
    path = tmp_path / "episodes.jsonl"
    MemoryStore(path).add(EP)
    MemoryStore(path).add({**EP, "incident_type": "registration_reject"})
    assert len(MemoryStore(path).load()) == 2


def test_load_skips_corrupt_lines(tmp_path):
    path = tmp_path / "episodes.jsonl"
    MemoryStore(path).add(EP)
    with path.open("a", encoding="utf-8") as fh:
        fh.write("{not json]\n")
        fh.write("")
    MemoryStore(path).add({**EP, "incident_type": "registration_reject"})
    episodes = MemoryStore(path).load()
    assert [ep.incident_type for ep in episodes] == \
        ["auth_failure", "registration_reject"]


def test_load_missing_store_is_empty(tmp_path):
    assert make_store(tmp_path).load() == []


def test_query_by_incident_type(tmp_path):
    store = make_store(tmp_path)
    store.add(EP)
    store.add({**EP, "incident_type": "registration_reject",
               "narrative": "IMSI unknown in UDM, reject cause 12",
               "cited_evidence": [
                   {"message": "5GMMRegistrationReject", "cause": 12,
                    "ts": 2.0}]})
    out = query_episodic_memory(store, incident_type="registration_reject")
    assert "registration_reject" in out
    assert "IMSI unknown" in out
    assert "wrong long-term key" not in out


def test_query_by_message_and_cause(tmp_path):
    store = make_store(tmp_path)
    store.add(EP)
    store.add({**EP, "incident_type": "pdu_session_timeout",
               "narrative": "SMF never answered: request unpaired",
               "cited_evidence": [
                   {"message": "5GMMStatus", "cause": 90, "ts": 11.2}]})
    for out in [query_episodic_memory(store, message="5GMMStatus"),
                query_episodic_memory(store, cause=90),
                query_episodic_memory(store, message="5GMMStatus", cause=90)]:
        assert "SMF never answered" in out
    # cause 90 must not match the auth_failure episode...
    assert "wrong long-term key" not in query_episodic_memory(store, cause=90)
    # ...and message+cause must co-occur in one evidence item
    assert "wrong long-term key" not in query_episodic_memory(
        store, message="5GMMStatus", cause=21)


def test_query_most_recent_first_with_limit(tmp_path):
    store = make_store(tmp_path)
    store.add({**EP, "incident_type": "registration_reject",
               "narrative": "older episode"})
    store.add({**EP, "incident_type": "registration_timeout",
               "narrative": "newer episode"})
    out = query_episodic_memory(store, limit=1)
    assert "newer episode" in out
    assert "older episode" not in out
    assert "1 more match(es) not shown" in out
    # without a limit both appear, newest first
    out = query_episodic_memory(store)
    assert out.index("newer episode") < out.index("older episode")


def test_empty_store_and_no_matches(tmp_path):
    store = make_store(tmp_path)
    assert query_episodic_memory(store).startswith(
        "Episodic memory is empty")
    store.add(EP)
    out = query_episodic_memory(store, cause=99)
    assert "no Episode matches the filters" in out
    assert "1 Episode(s) stored" in out


def test_observation_lists_evidence(tmp_path):
    store = make_store(tmp_path)
    store.add(EP)
    out = query_episodic_memory(store)
    assert "cited: 5GMMAuthenticationFailure cause=21 @1.000s" in out


def test_cited_evidence_fields_optional(tmp_path):
    store = make_store(tmp_path)
    store.add({**EP, "cited_evidence": [{"message": "NGSetupRequest"}]})
    out = query_episodic_memory(store, message="NGSetupRequest")
    assert "cited: NGSetupRequest" in out


# --- post-hoc CoALA consolidation ---

def test_consolidate_writes_episode(tmp_path):
    store = make_store(tmp_path)
    episode, wrote = consolidate(Episode(**EP), store)
    assert wrote is True
    assert store.load() == [episode]


def test_consolidate_skips_duplicate_run(tmp_path):
    store = make_store(tmp_path)
    first, wrote = consolidate(Episode(**EP), store)
    assert wrote is True
    # a re-run of the same capture yields the same incident + evidence;
    # the (possibly reworded) narrative does not change the record
    rerun = Episode(**{**EP, "narrative": "reworded on re-run"})
    second, wrote = consolidate(rerun, store)
    assert wrote is False
    assert second == first
    assert len(store.load()) == 1


def test_consolidate_same_incident_different_capture_written(tmp_path):
    store = make_store(tmp_path)
    first, wrote = consolidate(Episode(**EP), store)
    assert wrote is True
    other = Episode(**{**EP, "cited_evidence": [
        {"message": "5GMMAuthenticationFailure", "cause": 21, "ts": 9.9}]})
    _, wrote = consolidate(other, store)
    assert wrote is True  # different ts: a different capture, record it
    assert len(store.load()) == 2


def test_consolidate_same_evidence_different_type_written(tmp_path):
    store = make_store(tmp_path)
    _, wrote = consolidate(Episode(**EP), store)
    assert wrote is True
    other = Episode(**{**EP, "incident_type": "registration_reject"})
    _, wrote = consolidate(other, store)
    assert wrote is True
    assert len(store.load()) == 2
