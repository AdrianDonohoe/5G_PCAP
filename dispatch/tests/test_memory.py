"""Episodic memory: the dispatch Episode store, the structured scorer,
and the objective context seeded into the root-cause investigation.

Groq-free by construction (ADR-0002): the memory path is local file I/O
and strict equality — no embeddings, no API calls, no model downloads.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from dispatch.memory import Episode, EpisodeStore, memory_context

T0 = datetime(2026, 8, 31, 12, 0, 0, tzinfo=timezone.utc)


def _episode(store, incident_id, *, procedure=None, causes=(), keys=(),
             action=None, narrative="past", decision="approved-dry-run",
             created_at=None):
    ep = Episode(incident_id=incident_id, procedure=procedure,
                 causes=list(causes),
                 evidence_keys=[{"key": k, "value": v} for k, v in keys],
                 action=action, narrative=narrative, decision=decision,
                 created_at=created_at or T0)
    store.add(ep)
    return ep


@pytest.fixture
def event():
    return {"procedure": "n4_upf_timeout",
            "description": "the UPF never answers"}


@pytest.fixture
def evidence():
    # The scorer reads only each item's cause and keys — full items are
    # passed for honesty, matching the post-specialist inventory shape.
    return [
        {"source": "pcap", "kind": "x", "ts": 1.0, "entry": "x",
         "cause": "NAS cause 38", "endpoints": None,
         "keys": {"nf": "upf", "teid": "0x12345678"}, "citation": "n4:1"},
        {"source": "kpi", "kind": "x", "ts": 2.0, "entry": "x",
         "cause": None, "endpoints": None, "keys": {"flow_id": 1},
         "citation": "kpi.x"},
    ]


# --- the store: append-only, reloads across instances, skips corrupt ---

def test_store_appends_and_reloads_across_instances(tmp_path, event):
    path = tmp_path / "episodes.jsonl"
    store = EpisodeStore(path)
    _episode(store, "inc-1", procedure="n4_upf_timeout")
    _episode(store, "inc-2", procedure="n4_upf_timeout")
    reloaded = EpisodeStore(path).load()
    assert [ep.incident_id for ep in reloaded] == ["inc-1", "inc-2"]


def test_store_skips_corrupt_lines(tmp_path, event):
    path = tmp_path / "episodes.jsonl"
    store = EpisodeStore(path)
    _episode(store, "inc-1", procedure="n4_upf_timeout")
    with path.open("a", encoding="utf-8") as fh:
        fh.write("{not json at all\n")
        fh.write(json.dumps({"incident_id": "inc-x"}) + "\n")  # schema-invalid
    _episode(store, "inc-2", procedure="n4_upf_timeout")
    assert [ep.incident_id for ep in EpisodeStore(path).load()] == \
        ["inc-1", "inc-2"]


def test_episode_rejects_unknown_decision(tmp_path):
    with pytest.raises(ValidationError):
        Episode(incident_id="inc-1", narrative="", decision="maybe")


def test_episode_allows_honest_empty_narrative(tmp_path):
    # An incident decided without a root cause (all specialists failed)
    # is still remembered — the narrative is the honest fallback "".
    ep = Episode(incident_id="inc-1", narrative="", decision="rejected")
    assert ep.narrative == ""


# --- the scorer: 3/cause key, 2/same procedure, 1/evidence key ---

def test_memory_context_empty_store_returns_empty(tmp_path, event, evidence):
    assert memory_context(EpisodeStore(tmp_path / "e.jsonl"),
                          event, evidence) == ""


def test_memory_context_ranks_by_score_and_cuts_at_top_three(tmp_path, event,
                                                             evidence):
    store = EpisodeStore(tmp_path / "episodes.jsonl")
    # Same procedure + shared cause key: 2 + 3 = 5.
    _episode(store, "inc-ca", procedure="n4_upf_timeout",
             causes=["NAS cause 38"], narrative="cause-match",
             created_at=T0)
    # Same procedure + one shared evidence key: 2 + 1 = 3.
    _episode(store, "inc-k", procedure="n4_upf_timeout",
             keys=[("flow_id", 1)], narrative="key-match",
             created_at=T0 + timedelta(seconds=10))
    # Same procedure, nothing shared: 2 — passes the threshold.
    _episode(store, "inc-p", procedure="n4_upf_timeout", narrative="proc-only",
             created_at=T0 + timedelta(seconds=20))
    # Different procedure, one shared key: 1 — below the threshold.
    _episode(store, "inc-low", procedure="other", keys=[("nf", "upf")],
             narrative="below-threshold",
             created_at=T0 + timedelta(seconds=30))
    text = memory_context(store, event, evidence)
    assert "(3 of 4 Episode(s))" in text
    assert text.index("cause-match") < text.index("key-match") \
        < text.index("proc-only")
    assert "below-threshold" not in text


def test_memory_context_newest_first_on_equal_scores(tmp_path, event,
                                                     evidence):
    store = EpisodeStore(tmp_path / "episodes.jsonl")
    _episode(store, "inc-old", procedure="n4_upf_timeout", narrative="older",
             created_at=T0)
    _episode(store, "inc-new", procedure="n4_upf_timeout", narrative="newer",
             created_at=T0 + timedelta(seconds=60))
    text = memory_context(store, event, evidence)
    assert text.index("newer") < text.index("older")


def test_memory_context_renders_decision_and_keys(tmp_path, event, evidence):
    store = EpisodeStore(tmp_path / "episodes.jsonl")
    _episode(store, "inc-1", procedure="n4_upf_timeout",
             causes=["NAS cause 38"], keys=[("nf", "upf")],
             action="restart_nf", decision="approved-executed",
             narrative="the UPF is stuck")
    text = memory_context(store, event, evidence)
    assert "inc-1" in text
    assert "the UPF is stuck" in text
    assert "nf=upf" in text
    assert "NAS cause 38" in text
    assert "action: restart_nf" in text
    assert "decision: approved-executed" in text


def test_memory_context_without_procedure_scores_keys_only(tmp_path, event,
                                                           evidence):
    # A human-raised event may carry no procedure; the key/cause weights
    # alone decide relevance — never the procedure.
    store = EpisodeStore(tmp_path / "episodes.jsonl")
    _episode(store, "inc-1", procedure=None, causes=["NAS cause 38"],
             narrative="cause-only")
    text = memory_context(store, {"procedure": None}, evidence)
    assert "cause-only" in text
