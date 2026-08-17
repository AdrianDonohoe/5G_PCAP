"""query_3gpp_spec retrieval-logic tests with a deterministic stub embedder.

The real embedding model (BAAI/bge-small-en-v1.5 via fastembed) downloads
~100 MB on first use; the pytest suite must not require that download, so
ranking / caching / formatting are tested against a bag-of-keyword stub.
The real model is exercised by an ad-hoc acceptance pass, not the suite
(ADR-0002: the test suite stays cheap).
"""

import json
from pathlib import Path

import numpy as np
import pytest

from triage.specrag import SpecIndex, load_chunks, query_3gpp_spec

VOCAB = ["authentication", "reject", "pdu", "session", "pfcp", "slice",
         "cause", "timeout", "registration"]


def stub_embed(texts):
    """Bag-of-keyword vectors over VOCAB."""
    out = []
    for text in texts:
        vector = np.zeros(len(VOCAB), dtype=np.float32)
        lowered = text.lower()
        for i, word in enumerate(VOCAB):
            if word in lowered:
                vector[i] = 1.0
        out.append(vector)
    return np.asarray(out, dtype=np.float32)


def write_corpus(path, chunks):
    path.write_text(
        "\n".join(json.dumps(c) for c in chunks) + "\n")


def make_index(tmp_path, chunks, embed=stub_embed):
    corpus = tmp_path / "chunks.jsonl"
    write_corpus(corpus, chunks)
    return SpecIndex(embed=embed, name="stub", corpus_path=corpus,
                     index_dir=tmp_path / "index"), corpus


CORPUS = [
    {"spec": "24501", "text": "authentication procedures and MAC "
                              "verification failure cause reject"},
    {"spec": "29244", "text": "pdu session establishment over pfcp "
                              "between smf and upf"},
    {"spec": "24501", "text": "slice cause code dnn not supported in "
                              "the slice"},
]


def test_search_ranks_by_keyword_similarity(tmp_path):
    index, _ = make_index(tmp_path, CORPUS)
    hits = index.search("pdu session establishment")
    assert [c["text"] for c, _ in hits][0] == CORPUS[1]["text"]
    scores = [score for _, score in hits]
    assert scores == sorted(scores, reverse=True)


def test_top_k_limit(tmp_path):
    index, _ = make_index(tmp_path, CORPUS)
    hits = index.search("authentication slice", top_k=2)
    assert len(hits) == 2


def test_index_cached_across_instances(tmp_path):
    index, corpus_path = make_index(tmp_path, CORPUS)
    index.search("authentication")  # builds and caches the vectors
    calls = []
    second = SpecIndex(embed=lambda texts: calls.append(texts) or
                       stub_embed(texts), name="stub", corpus_path=corpus_path,
                       index_dir=tmp_path / "index")
    hits = second.search("authentication")
    # cache hit: only the query is embedded, never the corpus again
    assert calls == [["authentication"]]
    assert hits == index.search("authentication")


def test_cache_rebuilt_when_corpus_changes(tmp_path):
    index, corpus_path = make_index(tmp_path, CORPUS)
    index.search("authentication")
    calls = []
    extended = CORPUS + [{"spec": "38413",
                          "text": "ngap initialue message registration"}]
    write_corpus(corpus_path, extended)
    second = SpecIndex(embed=lambda texts: calls.append(texts) or
                       stub_embed(texts), name="stub", corpus_path=corpus_path,
                       index_dir=tmp_path / "index")
    second.search("registration")
    # the changed corpus invalidated the cache: re-embedded (4 chunks),
    # then the query
    assert len(calls) == 2 and len(calls[0]) == 4


def test_observation_format(tmp_path):
    index, _ = make_index(tmp_path, CORPUS)
    observation = query_3gpp_spec("pdu session", top_k=1, index=index)
    assert observation.startswith(
        '3GPP spec retrieval for "pdu session" (1 hit(s)):')
    assert "score=" in observation
    assert CORPUS[1]["text"] in observation


def test_unavailable_index_degrades(tmp_path):
    def failing_embed(texts):
        raise RuntimeError("no model here")
    index, _ = make_index(tmp_path, CORPUS, embed=failing_embed)
    observation = query_3gpp_spec("authentication", index=index)
    assert observation.startswith("3GPP spec index unavailable")
    assert "no model here" in observation


def test_lexical_bonus_boosts_exact_phrase():
    from triage.specrag import _lexical_bonus
    texts = ["authentication reject handling",
             "the DNN not supported or not subscribed in the slice case"]
    bonus = _lexical_bonus(
        "cause 91 DNN not supported or not subscribed in the slice", texts)
    assert bonus[1] == pytest.approx(0.15)
    assert bonus[0] == 0.0


def test_search_boosts_exact_query_phrase(tmp_path):
    chunks = [
        {"spec": "24501", "text": "authentication mac verification failure"},
        {"spec": "24501", "text": "authentication procedures"},
    ]
    index, _ = make_index(tmp_path, chunks)
    hits = index.search("authentication mac verification failure")
    scores = {c["text"]: s for c, s in hits}
    # equal stub cosine (both match only "authentication"); the exact
    # 4-word phrase must lift the first chunk above the second
    assert hits[0][0]["text"] == "authentication mac verification failure"
    assert scores["authentication mac verification failure"] == \
        pytest.approx(scores["authentication procedures"] + 0.15)


def test_loads_committed_corpus():
    manifest = json.loads(
        (Path(__file__).parent.parent / "corpus" / "manifest.json").read_text())
    assert len(load_chunks()) == sum(
        entry["chunks"] for entry in manifest["specs"].values())
    assert all("text" in chunk for chunk in load_chunks())
