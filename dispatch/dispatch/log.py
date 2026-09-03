"""The Log specialist agent: docker stdout logs for the event's time
window, with LLM extraction proposing Evidence items and a code-enforced
grounding check.

The pipeline: `docker compose logs --timestamps` pulls the windowed output
for the sandbox core services, the extraction proposes items, and each
proposal's citation must be an exact line of the windowed pull — a cited
line outside the window (or fabricated) is rejected, never recorded.
Citations are exact log lines; the item's ts is read from the cited line's
docker timestamp prefix and its source is set in code, neither trusted to
the extraction. The docker subprocess and the extraction are stub seams
(runner/extractor injected in tests); the live extractor is a lazy
gpt-oss:120b via Groq predictor, mirroring triage's wiring. Groq-free by
construction: tests feed committed synthetic log fixtures, and a failing
seam degrades the node to no evidence."""

import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import dspy

from triage import tracing

# dspy treats the first segment of the model string as its provider and
# sends the rest; Groq's own model IDs carry an "openai/" vendor prefix
# (openai/gpt-oss-120b), hence the doubled prefix. Same pin as triage's
# search module (spec #23: models unchanged).
GROQ = ("openai/openai/gpt-oss-120b", "https://api.groq.com/openai/v1")


def run_docker_logs(sandbox_root, window: dict, runner=None) -> str:
    """Pull `docker compose logs --timestamps` for the event's time window
    from the sandbox core services and return the raw output. ``runner`` is
    the stub seam; the real run goes through subprocess.run."""
    root = Path(sandbox_root)
    command = (f"docker compose --project-directory {root}/core logs "
               f"--timestamps --since {_rfc3339(window['start'])} "
               f"--until {_rfc3339(window['end'])}")
    if runner is None:
        result = subprocess.run(command, shell=True, capture_output=True,
                                text=True)
    else:
        result = runner(command, shell=True)
    code = getattr(result, "returncode", result)
    if code != 0:
        detail = (getattr(result, "stderr", "") or "").strip()
        suffix = f": {detail}" if detail else ""
        raise ValueError(f"docker compose logs failed (exit {code}){suffix}")
    return getattr(result, "stdout", "") or ""


def _rfc3339(ts: float) -> str:
    """The event's epoch window bound as RFC3339 for docker --since/--until."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


class LogEvidenceSignature(dspy.Signature):
    """Propose Evidence items from windowed docker logs; every citation is
    one complete input line copied verbatim."""

    log_text: str = dspy.InputField(
        desc="docker compose logs output within the Alarm event's time "
             "window")
    incident: str = dspy.InputField(desc="the Alarm event description")
    items: str = dspy.OutputField(
        desc='JSON array of {"kind", "entry", "keys", "citation"} objects; '
             'citation is one complete input line, verbatim')


def _groq_lm():
    key = os.environ.get("GROQ_API_KEY")
    if not key:
        raise RuntimeError("GROQ_API_KEY is not set (ADR-0002: no local "
                           "model fallback)")
    lm = dspy.LM(GROQ[0], api_base=GROQ[1], api_key=key, cache=False,
                 max_tokens=8192)
    dspy.configure(lm=lm)
    # ADR-0009: arm LangSmith tracing if the gate is on; every dspy call
    # in this process (log extraction, proposal, the imported root-cause
    # search) then fans out runs tagged source="dispatch" into the shared
    # triage-dispatch project. Idempotent no-op with the gate off.
    tracing.install(source="dispatch")
    return lm


def default_extract():
    """extract(log_text, event) -> list of proposed item dicts. Built
    lazily: importing this module never requires GROQ_API_KEY or network
    (ADR-0002)."""
    predictor = dspy.Predict(LogEvidenceSignature)
    _groq_lm()

    def extract(log_text: str, event: dict) -> list[dict]:
        result = predictor(log_text=log_text,
                           incident=event.get("description", ""))
        proposals = json.loads(result.items)
        if not isinstance(proposals, list):
            raise ValueError("log extraction did not return a JSON array")
        return proposals

    return extract


_DOCKER_TS = re.compile(
    r"^[^|]+\|\s+(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:\d{2}))")


def _line_ts(line: str) -> float | None:
    """The ts of a compose log line, read from docker's `--timestamps`
    prefix (RFC3339), or None when the line carries none."""
    match = _DOCKER_TS.match(line)
    if not match:
        return None
    try:
        return datetime.fromisoformat(match.group(1)).timestamp()
    except ValueError:
        return None


def ground_log_item(proposed, windowed_lines: set[str],
                    window: dict) -> dict | None:
    """Ground one proposed item against the windowed pull, or reject it.
    The citation must be an exact line of the windowed output — a cited
    line outside the window (or fabricated) fails membership — and the
    line's own timestamp must fall inside the event's window, so the
    bounds are checked in code, not delegated to docker's --since/--until
    alone. The item's ts is read from the cited line's docker timestamp
    prefix, never from the proposal; kind and entry are required strings;
    source is set in code, never trusted to the extraction."""
    if not isinstance(proposed, dict):
        return None
    citation = proposed.get("citation")
    if not isinstance(citation, str):
        return None
    line = citation.rstrip("\r\n")
    if line not in windowed_lines:
        return None
    ts = _line_ts(line)
    if ts is None:
        return None
    if not (window["start"] <= ts <= window["end"]):
        return None
    kind = proposed.get("kind")
    entry = proposed.get("entry")
    if not isinstance(kind, str) or not kind \
            or not isinstance(entry, str) or not entry:
        return None
    keys = proposed.get("keys")
    return {
        "source": "log",
        "kind": kind,
        "ts": ts,
        "entry": entry,
        "cause": None,
        "endpoints": None,
        "keys": keys if isinstance(keys, dict) else {},
        "citation": line,
    }


def run_log_agent(event: dict, sandbox_root, log_runner=None,
                  extractor=None) -> list[dict]:
    """The Log specialist node: pull the docker stdout logs for the event's
    time window, let the LLM extraction propose Evidence items, and keep
    only items whose citation is an exact line of the windowed pull. The
    docker subprocess and the extraction are stub seams (ADR-0002); any
    failure yields no evidence — never an invented item."""
    window = event["time_window"]
    try:
        text = run_docker_logs(sandbox_root, window, runner=log_runner)
    except (ValueError, OSError, TypeError):
        return []
    windowed_lines = {line.rstrip("\r\n") for line in text.splitlines()}
    try:
        if extractor is None:
            extractor = default_extract()
        proposals = extractor(text, event)
    except Exception:
        # LLM failure modes are library-defined (missing key, quota,
        # schema); degrade like triage's run_lats, never crash.
        return []
    if not isinstance(proposals, list):
        return []
    items = []
    for proposed in proposals:
        item = ground_log_item(proposed, windowed_lines, window)
        if item is not None:
            items.append(item)
    return items
