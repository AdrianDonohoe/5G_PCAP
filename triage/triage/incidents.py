"""Incident detection: find failed Registration / PDU Session procedures in
5gcap's decode output, on both the N2 and SBI planes.

CONTEXT.md: an Incident is a single failed Procedure within one Flow — an
explicit Reject with a cause code, or a Partial Flow whose terminal message
never arrives. Detection is deterministic; the LATS search takes over from
the Incident description. The sandbox fixtures (ground truth in
sandbox/README.md) pin the real wire shapes this matches:

- an explicit reject: a procedure with outcome "reject", or a cause-bearing
  Reject/Status/Failure message (the slice case carries 5GMM STATUS #91 in
  a flow whose NGAP procedure records all read "accept");
- a timeout: a flow whose messages never produced a procedure record (the
  paused-AMF capture holds a lone RegistrationRequest), a partial flow, or a
  cause echoed on a *request* message (the blackholed SMF echoes the UE's
  PDU request back with #90, 10 s apart — no reject at all).

The SBI plane reuses the same two shape literals: an SBI procedure is a
request/response pair (HTTP status), so an explicit reject is a response
with status >= 400 and a timeout is a request never answered by capture
end. SBI incidents carry flow_id None — SBI messages are not correlated to
N2 flows — and cite the service name as their procedure.
"""

import re

PROCEDURE_LABELS = {"registration": "Registration",
                    "pdu_session_est": "PDU Session"}

_CAUSE_BEARING = re.compile(r"reject|status|failure", re.I)


def _procedure(flow: dict, failed: list[dict]) -> str:
    """The procedure the Incident is about: the failed one when a record
    exists, else inferred from the flow's message names."""
    if failed:
        kind = failed[0].get("kind") or ""
        return PROCEDURE_LABELS.get(kind, kind.replace("_", " ").title())
    names = " ".join(m.get("nas_inner") or m.get("nas") or m.get("ngap") or ""
                     for m in flow.get("messages") or [])
    if "PDUSession" in names or "5GSMPDU" in names:
        return "PDU Session"
    if "Registration" in names:
        return "Registration"
    return "unknown"


def _shape(messages: list[dict], failed: list[dict]) -> str:
    if any(p.get("outcome") == "reject" for p in failed):
        return "explicit reject"
    for msg in messages:
        name = msg.get("nas_inner") or msg.get("nas") or ""
        if msg.get("nas_cause") and _CAUSE_BEARING.search(name):
            return "explicit reject"
    return "no terminal message (timeout)"


def detect_incidents(n2: dict) -> list[dict]:
    """One Incident per failed Flow in the decode; golden flows are skipped.

    An outcome of "unknown" is not a failure (it is not an accept either,
    but N2 procedure records that never reached a terminal message do not
    exist at all — see the module docstring).
    """
    incidents = []
    for flow in n2.get("flows") or []:
        messages = flow.get("messages") or []
        failed = [p for p in flow.get("procedures") or []
                  if p.get("outcome") not in ("accept", "unknown")]
        causes = [m for m in messages if m.get("nas_cause")]
        timeout = bool(messages) and not flow.get("procedures") and not failed
        if not failed and not causes and not timeout and not flow.get("partial"):
            continue
        incident = {"plane": "n2", "flow_id": flow.get("flow_id"),
                    "procedure": _procedure(flow, failed),
                    "shape": _shape(messages, failed)}
        if causes:
            codes = sorted({m["nas_cause"].get("code") for m in causes
                            if m["nas_cause"].get("code")})
            incident["detail"] = "cause code(s) observed: " + \
                ", ".join(f"#{code}" for code in codes)
        incidents.append(incident)
    return incidents


def detect_sbi_incidents(sbi: dict) -> list[dict]:
    """One Incident per failed SBI procedure (reject or timeout)."""
    incidents = []
    for p in sbi.get("procedures") or []:
        if p.get("outcome") not in ("reject", "timeout"):
            continue
        incident = {"plane": "sbi", "flow_id": None,
                    "procedure": p.get("kind") or "unknown",
                    "shape": ("explicit reject" if p.get("outcome") == "reject"
                              else "no terminal message (timeout)")}
        if p.get("outcome") == "reject":
            incident["detail"] = "SBI status code(s) observed: " + \
                str(p.get("status"))
        incidents.append(incident)
    return incidents
