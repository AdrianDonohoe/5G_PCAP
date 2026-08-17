"""query_3gpp_spec: semantic retrieval over the committed 3GPP spec corpus
(corpus/chunks.jsonl, built by scripts/build_corpus.py).

ADR-0002: the corpus is dense technical prose (a query like "why would
authentication fail" must match phrasing like "MAC verification failure"),
so semantic retrieval earns its cost here even though episodic memory
doesn't. The corpus is embedded with a local CPU model (fastembed's
BAAI/bge-small-en-v1.5, 384-dim) on first use and cached under
corpus/cache/index/ (gitignored), keyed by model + chunks.jsonl sha256 so
the index rebuilds exactly when the corpus changes. The first build embeds
~3500 chunks and takes ~15-30 min of CPU on a 2-vCPU machine; afterwards
every run loads the cache. Nothing is uploaded; the only network use is
fastembed's one-time model download.

Retrieval failures degrade to an honest observation string rather than a
crash (ADR-0001: tools must never kill the search).
"""

import hashlib
import json
from pathlib import Path

import numpy as np

CORPUS = Path(__file__).resolve().parent.parent / "corpus"
CHUNKS = CORPUS / "chunks.jsonl"
INDEX_DIR = CORPUS / "cache" / "index"

MODEL = "BAAI/bge-small-en-v1.5"
TOP_K = 5


def load_chunks() -> list[dict]:
    # Split on "\n" only: the corpus text contains U+2028 line separators
    # from 3GPP's docx (see tests/test_corpus.py).
    return [json.loads(line) for line in CHUNKS.read_text().split("\n")
            if line]


def _lexical_bonus(query: str, texts: list[str]) -> np.ndarray:
    """A small constant bonus for chunks containing an exact query phrase.

    Evidence-driven queries cite exact strings ("cause 91 DNN not supported
    or not subscribed in the slice"); pure dense retrieval can rank those
    below near-paraphrases. The longest exact phrase of >=4 words wins.
    """
    words = query.lower().split()
    lowered = [text.lower() for text in texts]
    bonus = np.zeros(len(texts))
    for n in range(min(len(words), 8), 3, -1):
        for start in range(len(words) - n + 1):
            phrase = " ".join(words[start:start + n])
            if len(phrase) < 16:
                continue
            matches = [i for i, text in enumerate(lowered) if phrase in text]
            if matches:
                for i in matches:
                    bonus[i] += 0.15
                return bonus
    return bonus


def _embed_batch(texts: list[str]) -> np.ndarray:
    # Lazy import: fastembed (onnxruntime) loads only when the index is
    # actually built, not for every triage invocation that imports this.
    # cache_dir pinned under ~/.cache (fastembed's default is /tmp, which
    # a reboot clears, forcing a re-download of the ~100 MB model).
    from fastembed import TextEmbedding
    model = TextEmbedding(MODEL, cache_dir=str(Path.home() / ".cache" / "fastembed"))
    # Embed in small slices: the onnxruntime arena holds ~20 MB of RSS per
    # text in a batch (measured: 64 texts ~2.4 GB stable, 128 ~2.9 GB,
    # 256 ~5.4 GB — the kernel OOM-killed 256-text builds on this 7.8 GB
    # VM). 64 texts keeps peak RSS ~2.4 GB with the same per-text speed.
    parts = []
    for i in range(0, len(texts), 64):
        parts.append(np.asarray(
            list(model.embed(texts[i:i + 64], batch_size=64)),
            dtype=np.float32))
    return np.vstack(parts)


class SpecIndex:
    """Lazy embedding index over chunks.jsonl, cached on disk."""

    def __init__(self, embed=_embed_batch, name: str = MODEL,
                 corpus_path: Path = CHUNKS, index_dir: Path = INDEX_DIR):
        self.embed = embed
        self.name = name
        self.corpus_path = corpus_path
        self.index_dir = index_dir
        self._chunks: list[dict] | None = None
        self._vectors: np.ndarray | None = None

    def _cache_path(self) -> Path:
        sha = hashlib.sha256(self.corpus_path.read_bytes()).hexdigest()
        return self.index_dir / f"{self.name.replace('/', '_')}-{sha[:16]}.npy"

    def ensure(self) -> None:
        """Load the cached index, or build it from the corpus once."""
        if self._vectors is not None:
            return
        cache = self._cache_path()
        chunks = [json.loads(line) for line in
                  self.corpus_path.read_text().split("\n") if line]
        if cache.exists():
            vectors = np.load(cache)
        else:
            vectors = self.embed([c["text"] for c in chunks])
            if vectors.shape[0] != len(chunks):
                raise ValueError(f"embedder returned {vectors.shape[0]} "
                                 f"vectors for {len(chunks)} chunks")
            self.index_dir.mkdir(parents=True, exist_ok=True)
            np.save(cache, vectors)
        self._chunks = chunks
        self._vectors = vectors

    def search(self, query: str, top_k: int = TOP_K) -> list[tuple[dict, float]]:
        """Top-k chunks by cosine similarity, best first."""
        self.ensure()
        query_vec = np.asarray(self.embed([query]), dtype=np.float32)[0]
        q_norm = float(np.linalg.norm(query_vec))
        norms = np.linalg.norm(self._vectors, axis=1)
        if q_norm == 0.0:
            return []
        scores = (self._vectors @ query_vec) / (norms * q_norm)
        scores = scores + _lexical_bonus(
            query, [c["text"] for c in self._chunks])
        best = np.argsort(scores)[::-1][:top_k]
        return [(self._chunks[int(i)], float(scores[i]))
                for i in best if scores[i] > 0.0]


def query_3gpp_spec(query: str, top_k: int = TOP_K,
                    index: SpecIndex | None = None) -> str:
    """The Action's observation: the top_k spec chunks for a question."""
    try:
        hits = (index or SpecIndex()).search(query, top_k)
    except Exception as exc:  # offline / model missing: honest degradation
        return (f"3GPP spec index unavailable ({exc}); no spec chunks "
                f"retrieved for: {query}")
    if not hits:
        return f'3GPP spec retrieval for "{query}": no matching chunks'
    lines = [f'3GPP spec retrieval for "{query}" ({len(hits)} hit(s)):', ""]
    for i, (chunk, score) in enumerate(hits, 1):
        lines.append(f"[{i}] score={score:.3f}")
        lines.append(chunk["text"])
        lines.append("")
    return "\n".join(lines)
