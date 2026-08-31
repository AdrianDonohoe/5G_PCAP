"""Episodic memory: the dispatch Episode store, the structured scorer,
and the objective context seeded into the root-cause investigation.

CONTEXT.md: an Episode is a decided incident — its signature (procedure,
scenario, evidence keys), the decision, and, once the operator closes it,
its Outcome. The execute node writes it at decision time, whatever the
decision (spec #33); the Outcome is appended later, at close.

The backend mirrors triage's proven MemoryStore pattern — an append-only
local JSON file store whose corrupt lines are skipped on load — and the
structured-lookup stance triage's ADR first argued: strict key equality,
no embeddings, no API calls, ever. The scorer is shared with Runbook
matching (ticket #35): 3 per shared cause key, 2 for the same procedure,
1 per shared evidence key; matches score at least 2; top 3, newest first.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

DECISIONS = Literal["approved-dry-run", "approved-executed", "rejected"]


class EvidenceKey(BaseModel):
    """One (key, value) pair from the correlated evidence inventory."""
    key: str
    value: str | int | float


class Episode(BaseModel):
    """A decided incident (CONTEXT.md): the match keys — incident id,
    procedure, scenario, the evidence keys and causes, the action — plus
    the narrative root cause, the justification, the decision, and the
    Outcome once the operator closes the incident. The narrative may be
    the honest fallback "" (an incident decided without a root cause is
    still remembered)."""
    incident_id: str
    procedure: str | None = None
    scenario: str | None = None
    evidence_keys: list[EvidenceKey] = Field(default_factory=list)
    causes: list[str] = Field(default_factory=list)
    action: str | None = None
    narrative: str
    justification: str | None = None
    decision: DECISIONS
    outcome: Literal["resolved", "unresolved"] | None = None
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc))


class EpisodeStore:
    """Append-only JSONL file of Episodes."""

    def __init__(self, path: Path):
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
                continue  # corrupt record: skip rather than fail the path
        return episodes


def _evidence_keys(episode: Episode) -> set[tuple[str, str]]:
    return {(key.key, str(key.value)) for key in episode.evidence_keys}


def memory_context(store: EpisodeStore, event: dict, evidence: list) -> str:
    """Relevant past Episodes for one incident, to seed the search
    objective. Retrieval is structural, not semantic: per Episode, 3 per
    shared cause key, 1 per shared evidence key, 2 for the same
    procedure; Episodes scoring below 2 are not relevant. Most relevant
    first, newest first on ties, top 3. An empty store (or nothing
    relevant) returns "" — the objective is built as if memory never
    existed."""
    episodes = store.load()
    if not episodes:
        return ""
    procedure = event.get("procedure")
    causes = {item["cause"] for item in evidence if item.get("cause")}
    seen_keys = {(key, str(value))
                 for item in evidence
                 for key, value in (item.get("keys") or {}).items()}
    scored = []
    for ep in episodes:
        shared_causes = set(ep.causes) & causes
        shared_keys = _evidence_keys(ep) & seen_keys
        score = (3 * len(shared_causes) + len(shared_keys)
                 + (2 if procedure is not None and ep.procedure == procedure
                    else 0))
        if score >= 2:
            scored.append((score, ep))
    if not scored:
        return ""
    scored.sort(key=lambda pair: (pair[0], pair[1].created_at), reverse=True)
    lines = [f"Past similar incidents retrieved from episodic memory "
             f"({len(scored)} of {len(episodes)} Episode(s)):"]
    for i, (_, ep) in enumerate(scored[:3], 1):
        lines.append(f"[{i}] {ep.incident_id}  {ep.created_at.isoformat()}")
        if ep.narrative:
            lines.append(f"    {ep.narrative}")
        details = []
        if ep.evidence_keys:
            details.append("keys: " + ", ".join(
                f"{key.key}={key.value}" for key in ep.evidence_keys))
        if ep.causes:
            details.append("causes: " + ", ".join(ep.causes))
        if ep.action:
            details.append(f"action: {ep.action}")
        detail_part = f" · {'; '.join(details)}" if details else ""
        lines.append(f"    decision: {ep.decision}{detail_part}")
    return "\n".join(lines)
