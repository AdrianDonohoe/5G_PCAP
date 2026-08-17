"""Regression tests for the committed 3GPP spec corpus.

chunks.jsonl + manifest.json are committed (only the zip/docx cache under
corpus/cache/ is gitignored), so these tests run offline and pin the corpus
shape that the query_3gpp_spec tool will index.
"""

import json
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHUNKS = ROOT / "corpus" / "chunks.jsonl"
MANIFEST = ROOT / "corpus" / "manifest.json"

EXPECTED_SPECS = {"24501", "38413", "29244"}

# The NAS causes that appear in the sandbox failure-injection fixtures; each
# must be retrievable from the TS 24.501 chunks (compared lowercased: the
# decoder capitalizes "Synch failure" while 24.501's cause table writes
# "synch failure").
FIXTURE_CAUSES = [
    "5GS services not allowed",                           # 5GMM #7
    "synch failure",                                      # 5GMM #21
    "insufficient resources for specific slice and dnn",  # 5GSM #67
    "payload was not forwarded",                          # 5GMM #90
    "dnn not supported or not subscribed in the slice",   # 5GMM #91
]


@lru_cache(maxsize=1)
def _chunks():
    # Split on "\n" only: the corpus text contains U+2028 line separators
    # from 3GPP's docx, which str.splitlines() would also split on, breaking
    # json.loads mid-string. The build script's json.dumps only emits real
    # newlines as escaped \n, so "\n" alone is a faithful record separator.
    return [json.loads(line) for line in CHUNKS.read_text().split("\n")
            if line]


@lru_cache(maxsize=1)
def _manifest():
    return json.loads(MANIFEST.read_text())


def test_manifest_covers_the_three_specs():
    m = _manifest()
    assert set(m["specs"]) == EXPECTED_SPECS
    for entry in m["specs"].values():
        assert entry["token"] and entry["zip_sha256"]
        assert entry["version"].startswith("19.")
        assert entry["chunks"] > 0


def test_chunk_count_matches_manifest():
    chunks = _chunks()
    m = _manifest()
    assert len(chunks) == sum(e["chunks"] for e in m["specs"].values())


def test_chunks_well_formed():
    by_spec = {spec: entry for spec, entry in _manifest()["specs"].items()}
    for chunk in _chunks():
        entry = by_spec[chunk["spec"]]
        assert chunk["title"] == entry["title"]
        assert chunk["version"] == entry["version"]
        assert chunk["token"] == entry["token"]
        assert chunk["text"].startswith(
            f'{entry["title"]} V{entry["version"]} | ')
        assert chunk["clause"] and chunk["heading"] and chunk["chars"] > 0


def test_fixture_causes_resolvable_in_24_501():
    nas5g = "\n".join(c["text"] for c in _chunks()
                      if c["spec"] == "24501").lower()
    for cause in FIXTURE_CAUSES:
        assert cause.lower() in nas5g, cause
