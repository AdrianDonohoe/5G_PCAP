"""The Incident Record: deterministic Markdown with six sections. The only
prose in it is the root-cause narrative and the proposal justification
(canned stubs in this slice — real LLM output lands in #30)."""

import json

from .executor import OBSERVE_ONLY_NOTE

_APPROVAL_LABELS = {
    "pending": "**pending**",
    "approved-dry-run": "**approved (dry-run)**",
    "approved-executed": "**approved (executed)**",
    "rejected": "**rejected**",
}


def render_record(rec: dict) -> str:
    """Render one incident record dict to deterministic Markdown."""
    event = rec["event"]
    lines = [f"# Incident Record — {event['incident_id']}", ""]

    lines += [
        "## Event", "",
        f"- Incident id: `{event['incident_id']}`",
        f"- Detected at: {event['detected_at']}",
        f"- Source: {event['source']}",
        f"- Procedure: {event.get('procedure') or '-'}",
        "- Time window: "
        f"{event['time_window']['start']} → {event['time_window']['end']}",
        "", event.get("description", ""), "",
    ]

    lines += ["## Correlation graph", ""]
    for index, item in enumerate(rec["evidence"]):
        keys = ", ".join(f"{k}={v}" for k, v in item["keys"].items())
        lines.append(f"- [{index}] {item['source']} {item['kind']}: "
                     f"{item['entry']} (keys: {keys}) — "
                     f"cited: {item['citation']}")
    if not rec["evidence"]:
        lines.append("- (no evidence)")
    lines.append("")
    for edge in rec["links"]:
        lines.append(f"- [{edge['a']}] ↔ [{edge['b']}] via "
                     f"{edge['key']}={edge['value']}")
    if not rec["links"]:
        lines.append("- no links")
    lines.append("")

    lines += ["## Root cause", "", rec["root_cause"], ""]

    proposal = rec["proposal"]
    lines += [
        "## Proposal", "",
        f"- Action: `{proposal['action']}`",
        f"- Arguments: `{json.dumps(proposal['args'], sort_keys=True)}`",
        "", proposal["justification"], "",
        "Commands (template-rendered):", "",
    ]
    for command in proposal["commands"]:
        lines.append(f"- {command}")
    if not proposal["commands"]:
        lines.append(f"- {OBSERVE_ONLY_NOTE}")
    lines += ["", f"Proposal hash: `{proposal['hash']}`", ""]

    label = _APPROVAL_LABELS.get(rec["approval"], f"**{rec['approval']}**")
    lines += ["## Approval status", "", f"Approval status: {label}", ""]

    lines += ["## Execution log", ""]
    for entry in rec["execution_log"]:
        lines.append(f"- {entry}")
    if not rec["execution_log"]:
        lines.append("- (empty)")
    return "\n".join(lines) + "\n"
