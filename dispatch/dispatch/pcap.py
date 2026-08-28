"""The PCAP specialist agent: `triage analyze` as a subprocess over the
decode, emitting Evidence items grounded in the decode inventory.

The pipeline: 5gcap decodes the captures to the merged export (reusing the
KPI agent's subprocess seam), triage analyzes that export, and each cited
claim in the resulting episodes must match an inventory entry exactly —
message name, timestamp within the displayed-precision tolerance, and the
claimed cause — or it is rejected, never recorded. The grounding rule
mirrors triage's own grounded_evidence; citations name the decode handle
(n4:5, flow:1:3, sbi:2). The triage subprocess is a stub seam (runner
injected in tests). Groq-free by construction: tests feed saved-run
fixtures, and a failing seam degrades the node to no evidence."""

import json
import shlex
import subprocess
import tempfile
from pathlib import Path

from .kpi import run_analyze

# triage's displayed-precision tolerance: the LLM cites ts values rounded
# to two decimals, and the real episodes sit within 5e-4 of the decode's
# floats (report._locate_message and search.grounded_evidence both use it).
TS_TOLERANCE = 5e-4


def message_inventory(export: dict) -> list[dict]:
    """One entry per decodable message name: {plane, handle, name, ts,
    cause, flow_id}. N2 flow messages contribute every name they carry
    (ngap, nas, nas_inner). Handles follow the evidence-listing vocabulary,
    which is 1-based — triage's listings enumerate from [1] and resolve
    ``msgs[idx - 1]``."""
    inventory = []
    for flow in export.get("flows") or []:
        flow_id = flow.get("flow_id")
        for i, msg in enumerate(flow.get("messages") or [], 1):
            for name in (msg.get("ngap"), msg.get("nas"),
                         msg.get("nas_inner")):
                if name and msg.get("ts") is not None:
                    inventory.append({
                        "plane": "n2", "handle": f"flow:{flow_id}:{i}",
                        "name": name, "ts": msg["ts"],
                        "cause": (msg.get("nas_cause") or {}).get("code"),
                        "flow_id": flow_id})
    for i, msg in enumerate(export.get("unassociated") or [], 1):
        if msg.get("ngap") and msg.get("ts") is not None:
            inventory.append({
                "plane": "n2", "handle": f"unassociated:{i}",
                "name": msg["ngap"], "ts": msg["ts"], "cause": None,
                "flow_id": None})
    for i, msg in enumerate((export.get("n4") or {}).get("messages") or [], 1):
        if msg.get("name") and msg.get("ts") is not None:
            inventory.append({
                "plane": "n4", "handle": f"n4:{i}", "name": msg["name"],
                "ts": msg["ts"], "cause": msg.get("cause_code"),
                "flow_id": msg.get("flow_id")})
    for i, msg in enumerate((export.get("sbi") or {}).get("messages") or [], 1):
        if msg.get("name") and msg.get("ts") is not None:
            inventory.append({
                "plane": "sbi", "handle": f"sbi:{i}", "name": msg["name"],
                "ts": msg["ts"], "cause": None,
                "flow_id": msg.get("flow_id")})
    return inventory


def locate_evidence(inventory: list[dict], cited) -> dict | None:
    """The inventory entry matching a cited claim exactly, or None: name
    equality, ts within TS_TOLERANCE, and — when a cause is claimed — cause
    equality. A null claimed cause is "not claimed", never a mismatch; a
    timestampless claim can never match (triage's grounded_evidence rule)."""
    if not isinstance(cited, dict) or cited.get("ts") is None:
        return None
    for entry in inventory:
        if entry["name"] != cited.get("message"):
            continue
        if abs(entry["ts"] - cited["ts"]) < TS_TOLERANCE:
            if cited.get("cause") is not None and \
                    entry["cause"] != cited["cause"]:
                continue  # right message, wrong cause: ungrounded
            return entry
    return None


def pcap_item(match: dict, kind: str) -> dict:
    """The Evidence item for one grounded claim: the inventory's exact
    (message, ts, cause) and the decode handle as the citation."""
    name, cause = match["name"], match["cause"]
    return {
        "source": "pcap",
        "kind": kind,
        "ts": match["ts"],
        "entry": name + (f" cause {cause}" if cause is not None else ""),
        "cause": str(cause) if cause is not None else None,
        "endpoints": None,
        "keys": ({"flow_id": match["flow_id"]}
                 if match["flow_id"] is not None else {}),
        "citation": match["handle"],
    }


def run_triage(export_path: Path, runner=None) -> list[dict]:
    """Run `triage analyze` over a decoded export and parse the results
    array it prints to stdout. ``runner`` is the stub seam; the real run
    goes through subprocess.run."""
    repo = Path(__file__).resolve().parents[2]
    command = (f"uv run --project {repo}/triage triage analyze "
               f"{shlex.quote(str(export_path))}")
    if runner is None:
        result = subprocess.run(command, shell=True, capture_output=True,
                                text=True)
    else:
        result = runner(command, shell=True)
    code = getattr(result, "returncode", result)
    if code != 0:
        detail = (getattr(result, "stderr", "") or "").strip()
        suffix = f": {detail}" if detail else ""
        raise ValueError(f"triage analyze failed (exit {code}){suffix}")
    try:
        results = json.loads(getattr(result, "stdout", "") or "")
    except json.JSONDecodeError:
        raise ValueError("triage analyze output is not JSON")
    if not isinstance(results, list):
        raise ValueError("triage analyze output is not a results array")
    return results


def run_pcap_agent(captures: dict, triage_runner=None) -> list[dict]:
    """The PCAP specialist node: decode the captures, run `triage analyze`
    over the export, and emit one Evidence item per cited claim that
    matches the decode inventory exactly (message name, timestamp, cause).
    Claims that do not match are rejected, never recorded; citations name
    the decode handle. No N2 capture, or any decode/triage failure, yields
    nothing — never an invented item."""
    if not captures.get("n2"):
        return []
    try:
        export = run_analyze(captures)
        inventory = message_inventory(export)
        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False,
                                          mode="w")
        try:
            json.dump(export, tmp)
            tmp.close()
            results = run_triage(tmp.name, triage_runner)
        finally:
            Path(tmp.name).unlink(missing_ok=True)
        items = []
        for result in results:
            if not isinstance(result, dict):
                continue
            episode = result.get("episode")
            if not isinstance(episode, dict):
                continue
            kind = result.get("shape") or f"{result.get('plane') or 'pcap'} "\
                f"{result.get('procedure') or 'incident'}"
            for cited in episode.get("cited_evidence") or []:
                match = locate_evidence(inventory, cited)
                if match is not None:
                    items.append(pcap_item(match, kind))
        return items
    except (ValueError, OSError, TypeError):
        return []
