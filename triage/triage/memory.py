"""Episodic memory: the local JSON store of finalized triage Episodes, the
query_episodic_memory lookup tool, and the post-hoc CoALA consolidation.

CONTEXT.md: an Episode is written once, post-hoc, after a Hypothesis is
finalized — the Hypothesis plus the Evidence it cited (not the full
Trajectory). `consolidate` below is that post-hoc write: it records an
Episode exactly once, skipping a re-run of the same capture.

ADR-0002: the backend is a plain local JSON/file store, not a vector DB —
v1 is single-machine and eval-driven, so structured lookup (by
incident_type, by cited message type, by cause) beats semantic retrieval
for a store this small.

The store is append-only; corrupt lines are skipped on load rather than
killing the tool (ADR-0001: degrade, don't crash).
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

INCIDENT_TYPES = Literal[
    "auth_failure",
    "registration_reject",
    "registration_timeout",
    "pdu_session_reject_slice",
    "pdu_session_reject_other",
    "pdu_session_timeout",
    "pdu_session_rsp_timeout",
    "sbi_udm_timeout",
    "sbi_nssf_reject",
    "n4_upf_timeout",
]

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "memory" / "episodes.jsonl"


class CitedEvidence(BaseModel):
    """One piece of Evidence from 5gcap's decode output."""
    message: str             # NGAP/NAS message name or SBI service name
    cause: int | None = None  # NAS cause code, when the message carries one
    ts: float | None = None   # message timestamp in the capture


class Episode(BaseModel):
    """A finalized Hypothesis + the Evidence it cited (CONTEXT.md).

    The completeness bar is enforced here: a Hypothesis with no Evidence is
    not a valid Hypothesis, so an Episode with no cited evidence does not
    validate.
    """
    incident_type: INCIDENT_TYPES
    narrative: str = Field(min_length=1)
    cited_evidence: list[CitedEvidence] = Field(min_length=1)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc))


class MemoryStore:
    """Append-only JSONL file of Episodes."""

    def __init__(self, path: Path = DEFAULT_PATH):
        self.path = path

    def add(self, episode: Episode | dict) -> Episode:
        """Validate and append one Episode."""
        ep = episode if isinstance(episode, Episode) \
            else Episode.model_validate(episode)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(ep.model_dump_json() + "\n")
        return ep

    def load(self) -> list[Episode]:
        """All Episodes, oldest first; unparseable lines are skipped."""
        if not self.path.exists():
            return []
        episodes = []
        for line in self.path.read_text(encoding="utf-8").split("\n"):
            if not line:
                continue
            try:
                episodes.append(Episode.model_validate_json(line))
            except Exception:
                continue  # corrupt record: skip rather than fail the tool
        return episodes


def _consolidation_key(episode: Episode) -> tuple:
    return (episode.incident_type,
            frozenset((ev.message, ev.ts)
                      for ev in episode.cited_evidence))


def consolidate(episode: Episode, store: MemoryStore
                ) -> tuple[Episode, bool]:
    """The CoALA memory-update: record the finalized Episode exactly once.

    Runs after the LATS search concludes (ADR-0001: post-hoc, never
    mid-search). The Episode — Hypothesis plus cited Evidence — is the
    distilled record; the full Trajectory is not stored. An Episode whose
    incident_type and cited (message, ts) pairs are already in the store
    (e.g. a re-run of the same capture) is not written again. Returns the
    stored Episode and whether this call wrote it.
    """
    key = _consolidation_key(episode)
    for existing in store.load():
        if _consolidation_key(existing) == key:
            return existing, False
    return store.add(episode), True


def _matches(episode: Episode, incident_type: str | None,
             message: str | None, cause: int | None) -> bool:
    if incident_type is not None and episode.incident_type != incident_type:
        return False
    if message is None and cause is None:
        return True
    # When both message and cause are given, one evidence item must satisfy
    # both ("have we seen <message> carrying <cause>").
    return any((message is None or ev.message == message)
               and (cause is None or ev.cause == cause)
               for ev in episode.cited_evidence)


def query_episodic_memory(store: MemoryStore, incident_type: str | None = None,
                          message: str | None = None, cause: int | None = None,
                          limit: int = 5) -> str:
    """The Action's observation: matching Episodes, most recent first.

    Filters are ANDed; a match without any filter returns the newest
    Episodes. `message` is an exact NGAP/NAS message name.
    """
    episodes = store.load()
    if not episodes:
        return "Episodic memory is empty (no Episodes stored)."
    matches = [ep for ep in episodes
               if _matches(ep, incident_type, message, cause)]
    matches.sort(key=lambda ep: ep.created_at, reverse=True)
    if not matches:
        return (f"Episodic memory: no Episode matches the filters "
                f"({len(episodes)} Episode(s) stored).")
    lines = [f"Episodic memory matches "
             f"({len(matches)} of {len(episodes)} Episode(s)):"]
    for i, ep in enumerate(matches[:limit], 1):
        cited = "; ".join(
            ev.message
            + (f" cause={ev.cause}" if ev.cause is not None else "")
            + (f" @{ev.ts:.3f}s" if ev.ts is not None else "")
            for ev in ep.cited_evidence)
        lines.append(f"[{i}] {ep.incident_type}  {ep.created_at.isoformat()}")
        lines.append(f"    {ep.narrative}")
        lines.append(f"    cited: {cited}")
    if len(matches) > limit:
        lines.append(f"    ... ({len(matches) - limit} more match(es) "
                     f"not shown)")
    return "\n".join(lines)
