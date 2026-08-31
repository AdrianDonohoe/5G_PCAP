"""Procedural memory: Runbooks — operator-authored, committed Markdown
files with small YAML frontmatter, the documented remediation for a
failure signature.

The frontmatter carries the whole structured contract: {slug, title,
procedure, added, symptoms, steps, resolution} — symptoms are structured
key:value match keys, steps the ordered prose, and the resolution is
exactly one vocabulary action with args that may use {placeholder} form.
Parsing validates every field, so a bad runbook fails loudly at load
time instead of silently shipping a runbook that can never match (an
unknown frontmatter key is a typo, and typos must not look like "never
matches").

Matching reuses the shared scorer shape from the episodic-memory slice
(spec #33): 3 per shared symptom key, 2 for the same procedure,
threshold 2, top 3, newest first — the newest-first tiebreak runs on the
runbook's ``added`` date (unknown dates sort oldest) with the slug as
the final deterministic tiebreak. It is a pure structured lookup over
the evidence keys — never log-pattern matching. The top matches are
rendered as context ahead of the incident for the proposer, whose
{placeholder} args bind from the incident's evidence keys at proposal
time (first occurrence in inventory order); a placeholder with no
evidence key to bind raises, and the proposal yields None — like every
other invalid selection. All of this is plain file I/O and dict
lookups: Groq-free (ADR-0002)."""

import json
import re
from datetime import date
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from .executor import ACTIONS
from .memory import EvidenceKey


class Resolution(BaseModel):
    """One vocabulary action; args may hold {placeholder} values."""
    action: str
    args: dict[str, str] = Field(default_factory=dict)


class Runbook(BaseModel):
    slug: str
    title: str
    procedure: str | None = None
    added: date | None = None
    symptoms: list[EvidenceKey] = Field(default_factory=list)
    steps: list[str] = Field(default_factory=list)
    resolution: Resolution


_FRONTMATTER_KEYS = {"slug", "title", "procedure", "added", "symptoms",
                     "steps", "resolution"}

_PLACEHOLDER_RE = re.compile(r"^\{(\w+)\}$")


def _split_frontmatter(text: str) -> tuple[str, str]:
    """(frontmatter yaml, body) — the body prose is carried by the steps,
    so callers ignore it."""
    if not text.startswith("---\n"):
        raise ValueError("runbook frontmatter missing — the file must "
                         "start with a --- block")
    rest = text[len("---\n"):]
    end = rest.find("\n---")
    if end == -1:
        raise ValueError("runbook frontmatter is not closed (---)")
    return rest[:end], rest[end + 4:]


def _scalar(value):
    """A plain YAML scalar (str, int, float) — not a bool, not a list."""
    if isinstance(value, bool) or \
            not isinstance(value, (str, int, float)):
        raise ValueError(f"{value!r} is not a scalar value")
    return value


def parse_runbook(path: Path) -> Runbook:
    """Parse and validate one committed runbook file. Any structural
    problem — bad YAML, an unknown key, an action outside the
    vocabulary, symptoms that are not key:value scalars, empty steps —
    raises ValueError."""
    frontmatter, _body = _split_frontmatter(Path(path).read_text())
    try:
        data = yaml.safe_load(frontmatter)
    except yaml.YAMLError as exc:
        raise ValueError(f"runbook frontmatter is not valid YAML: "
                         f"{exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("runbook frontmatter must be a YAML mapping")
    unknown = set(data) - _FRONTMATTER_KEYS
    if unknown:
        raise ValueError("unknown frontmatter key(s): "
                         + ", ".join(sorted(unknown)))
    slug = data.get("slug")
    title = data.get("title")
    if not isinstance(slug, str) or not slug:
        raise ValueError("runbook slug must be a non-empty string")
    if not isinstance(title, str) or not title:
        raise ValueError("runbook title must be a non-empty string")
    procedure = data.get("procedure")
    if procedure is not None and not isinstance(procedure, str):
        raise ValueError("runbook procedure must be a string or null")
    added = data.get("added")
    if added is not None and not isinstance(added, date):
        raise ValueError("runbook added must be a YYYY-MM-DD date")
    raw_symptoms = data.get("symptoms") or {}
    if not isinstance(raw_symptoms, dict):
        raise ValueError("runbook symptoms must be a key: value mapping")
    symptoms = [EvidenceKey(key=str(key), value=_scalar(value))
                for key, value in raw_symptoms.items()]
    steps = data.get("steps")
    if not isinstance(steps, list) or not steps or \
            not all(isinstance(step, str) and step for step in steps):
        raise ValueError("runbook steps must be a non-empty list of "
                         "prose strings")
    resolution = data.get("resolution")
    if not isinstance(resolution, dict):
        raise ValueError("runbook resolution must be a mapping with "
                         "action and args")
    action = resolution.get("action")
    if action not in ACTIONS:
        raise ValueError(f"{action!r} is not in the remediation vocabulary")
    raw_args = resolution.get("args") or {}
    if not isinstance(raw_args, dict):
        raise ValueError("runbook resolution args must be a mapping")
    args = {str(key): str(_scalar(value))
            for key, value in raw_args.items()}
    return Runbook(slug=slug, title=title, procedure=procedure,
                   added=added, symptoms=symptoms, steps=steps,
                   resolution=Resolution(action=action, args=args))


def load_runbooks(directory) -> list[Runbook]:
    """Load every committed runbook in the directory. A file that fails
    to parse is skipped (degrade, never crash — the same discipline as
    the Episode store's corrupt-line skip); a missing directory is an
    empty library."""
    directory = Path(directory)
    if not directory.is_dir():
        return []
    runbooks = []
    for path in sorted(directory.glob("*.md")):
        try:
            runbooks.append(parse_runbook(path))
        except (ValueError, OSError):
            continue
    return runbooks


def _evidence_keys(evidence) -> set[tuple[str, str]]:
    keys = set()
    for item in evidence:
        for key, value in (item.get("keys") or {}).items():
            keys.add((key, str(value)))
    return keys


def match_runbooks(runbooks, event: dict, evidence) -> list[Runbook]:
    """Match runbooks to the incident signature with the shared scorer
    shape (spec #33): 3 per shared symptom key, 2 for the same procedure
    (empty and null normalise to the same procedure-less signature),
    threshold 2, top 3, newest first — the runbook's ``added`` date,
    unknown dates oldest, slug as the final deterministic tiebreak.
    Pure structured lookup: never log-pattern matching, never the
    literal args."""
    procedure = event.get("procedure") or ""
    keys = _evidence_keys(evidence)
    scored = []
    for runbook in runbooks:
        shared = keys & {(symptom.key, str(symptom.value))
                         for symptom in runbook.symptoms}
        score = 3 * len(shared)
        if (runbook.procedure or "") == procedure:
            score += 2
        if score >= 2:
            scored.append((score, runbook))
    scored.sort(key=lambda pair: pair[1].slug)
    scored.sort(key=lambda pair: pair[1].added or date.min, reverse=True)
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [runbook for _score, runbook in scored[:3]]


def runbook_context(matches, evidence, total: int) -> str:
    """The context prepended ahead of the incident before the proposer
    call: the matched runbooks with their steps and resolution, then the
    incident's evidence keys, from which the proposer binds any
    {placeholder} resolution args."""
    lines = [f"Runbooks retrieved from procedural memory "
             f"({len(matches)} of {total} Runbook(s)):"]
    for index, runbook in enumerate(matches, 1):
        procedure = runbook.procedure or "(none)"
        symptoms = ", ".join(f"{s.key}={s.value}"
                             for s in runbook.symptoms) or "(none)"
        lines.append(f"[{index}] Runbook {runbook.slug} — {runbook.title}")
        lines.append(f"    procedure: {procedure} · symptoms: {symptoms}")
        if runbook.steps:
            lines.append("    steps:")
            lines += [f"      {n}. {step}"
                      for n, step in enumerate(runbook.steps, 1)]
        lines.append(f"    resolution: {runbook.resolution.action} "
                     f"{json.dumps(runbook.resolution.args)}")
    keys = ", ".join(f"{k}={v}" for k, v in sorted(_evidence_keys(evidence))) \
        or "(none)"
    lines.append(f"Evidence keys: {keys}")
    lines.append("Bind any {placeholder} resolution args from these keys.")
    return "\n".join(lines)


def bind_placeholders(args: dict, evidence) -> dict:
    """Substitute {placeholder} arg values from the incident's evidence
    keys — the first occurrence in inventory order wins. An arg whose
    placeholder names a key the evidence does not carry raises
    ValueError: an unbound placeholder yields no proposal, like every
    other invalid selection. Literal and non-string values pass
    through untouched."""
    bound = {}
    for key, value in args.items():
        if isinstance(value, str):
            match = _PLACEHOLDER_RE.match(value)
            if match:
                for item in evidence:
                    if match.group(1) in (item.get("keys") or {}):
                        value = item["keys"][match.group(1)]
                        break
                else:
                    raise ValueError(
                        f"placeholder {value!r} has no evidence key to bind")
        bound[key] = value
    return bound
