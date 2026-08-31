"""The CoALA feedback loop (spec #33, slice 3): closing a resolved,
executed incident with the operator's evidence drafts a Runbook proposal
for review — deterministically, with no LLM call, staged in the
proposed-runbooks location, and never touching the committed Runbooks.

The draft is the Episode's own record rendered as a runbook: the
concrete proposal args are copied literally (the operator generalizes to
{placeholder} form at promotion), the evidence keys become the symptoms,
and the diagnosis, remediation and justification become the steps. The
operator reviews the printed diff and promotes the file into the
committed directory by hand — the loop proposes, a human disposes.

The confirmation check is the same Golden-baseline comparison the
detect-kpi comparator performs, on fresh post-remediation captures: for
a rerun_capture action that is the capture scenario itself, otherwise
the event's capture names. All of this is file I/O and string templates:
Groq-free (ADR-0002)."""

import json
from datetime import date, datetime, timezone
from pathlib import Path

import yaml

from .memory import Episode
from .runbook import match_runbooks


def confirmation_check(proposal: dict, event: dict, sandbox_root) -> str:
    """The suggested command that confirms the remediation worked: rerun
    the capture scenario itself, or compare fresh capture KPIs against
    the Golden baseline with the event's capture names (basenames — the
    dispatch detect-kpi comparator takes capture paths, and the suggested
    check runs from the captures directory)."""
    if proposal.get("action") == "rerun_capture":
        scenario = (proposal.get("args") or {}).get("scenario", "")
        return f"bash {sandbox_root}/capture.sh --scenario {scenario}"
    captures = event.get("captures") or {}
    n2 = Path(captures.get("n2", "<n2-capture>")).name
    parts = [f"dispatch detect-kpi {n2}"]
    if captures.get("sbi"):
        parts.append(f"--sbi {Path(captures['sbi']).name}")
    if captures.get("n4"):
        parts.append(f"--n4 {Path(captures['n4']).name}")
    return " ".join(parts)


def draft_filename(episode: Episode) -> str:
    """The traceable draft name: the procedure and the incident id, so a
    promoted runbook carries its origin story."""
    return f"{episode.procedure or 'none'}-{episode.incident_id}.md"


def draft_text(episode: Episode) -> str:
    """The deterministic Runbook draft (spec #33): the episode's concrete
    args copied literally, the evidence keys as the symptoms, and the
    diagnosis, remediation and justification as the steps. Promotion is
    manual — the operator reviews the diff, generalizes the args to
    {placeholder} form where warranted, and moves the file into the
    committed directory."""
    args = episode.args or {}
    symptoms = {key.key: key.value for key in episode.evidence_keys}
    steps = [
        f"Diagnosis: {episode.narrative or '(no root cause recorded)'}",
        f"Remediation: {episode.action} {json.dumps(args)}",
    ]
    if episode.justification:
        steps.append(f"Justification: {episode.justification}")
    title = f"Apply {episode.action} after incident {episode.incident_id}"
    frontmatter = {
        "slug": draft_filename(episode)[:-3],
        "title": title,
        "procedure": episode.procedure or "",
        "added": date.today(),
        "symptoms": symptoms,
        "steps": steps,
        "resolution": {"action": episode.action, "args": dict(args)},
    }
    body = (f"# {title}\n\n"
            f"Drafted by `dispatch close {episode.incident_id}` from the "
            "episode's own record — a deterministic template, no LLM "
            "call. The args stay literal; generalize them to {placeholder} "
            "form and adjust the steps at promotion.\n")
    return ("---\n"
            + yaml.safe_dump(frontmatter, sort_keys=False)
            + "---\n\n" + body)


def write_draft(episode: Episode, proposed_dir: Path) -> Path:
    """Write the deterministic draft into the proposed-runbooks location
    — a staging area beside the committed runbooks, reviewed and promoted
    by hand. The loop never writes into the committed directory."""
    proposed_dir = Path(proposed_dir)
    proposed_dir.mkdir(parents=True, exist_ok=True)
    path = proposed_dir / draft_filename(episode)
    path.write_text(draft_text(episode))
    return path


def matching_runbook(runbooks, episode: Episode) -> bool:
    """Whether a committed Runbook already covers the episode's signature
    (spec #33) — the same shared scorer the propose node uses, over the
    episode's procedure and evidence keys. A covered signature needs no
    draft."""
    return bool(match_runbooks(
        runbooks,
        {"procedure": episode.procedure},
        [{"keys": {key.key: key.value for key in episode.evidence_keys}}]))


def outcome_section(outcome: str, evidence: str | None, check: str) -> str:
    """The Outcome block appended to the Incident Record at close: the
    verdict, the operator's evidence, the suggested confirmation check,
    and the close time."""
    closed = datetime.now(timezone.utc).isoformat()
    return "\n".join([
        "",
        "## Outcome",
        "",
        f"- **Verdict:** **{outcome}**",
        f"- **Operator evidence:** {evidence or '(none)'}",
        f"- **Suggested confirmation check:** `{check}`",
        f"- **Closed at:** {closed}",
        "",
    ])


def diff_new_file(text: str, path: str | None = None) -> str:
    """The draft as a reviewable new-file diff — every line prefixed
    with +, the header naming the file."""
    header = f"+++ {path}" if path else "+++ (new file)"
    return header + "\n" + "".join(f"+{line}" for line in text.splitlines(True))
