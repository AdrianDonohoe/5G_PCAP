"""The Proposal node: the LLM selects a remediation from the fixed
five-action vocabulary and drafts the justification, under ADR-0002's
guard rails.

The LLM contributes exactly three fields — action, args, justification —
and code enforces everything else: the action must name one of the
Executor's five vocabulary actions, the args must be a dict, and the
justification must be non-empty prose. ``run_proposal`` rebuilds the
proposal from those three fields alone, so anything else the LLM adds
(commands, hashes) is dropped — the recorded commands come only from the
Executor's deterministic templates, never LLM text. The propose node
then passes the selection through the Executor's render rail, whose
allowlists reject args outside the sandbox (unknown nf, path escape,
bad IMSI, unknown scenario); observe_only takes no args at all. An
invalid selection yields no proposal and the record says so honestly.

The proposer is the stub seam: ``run_proposal`` takes an injected
proposer callable (tests pass a canned selection); the live default's
predictor is a lazy Groq call built on demand, so importing this module
never requires GROQ_API_KEY or network (ADR-0002)."""

import json

import dspy

from .executor import ACTIONS
from .log import GROQ, _groq_lm


class ProposalSignature(dspy.Signature):
    """You select the remediation for a 5G lab incident. The selection
    must address the root-cause narrative, which is grounded evidence.
    Choose the action from the fixed five-action vocabulary and draft a
    one-or-two-sentence justification for the Incident Record. Reply
    with JSON only, in the template (args per action as shown):

    {"action": "<one of restart_nf, revert_config, reseed_subscriber,
    rerun_capture, observe_only>", "args": {<args for that action>},
    "justification": "<why this action addresses the root cause>"}

    Args per action:
    - restart_nf: {"nf": "<name of the network function to restart,
      e.g. upf>"}
    - revert_config: {"path": "<path of a config file under the
      sandbox, e.g. core/config/upf.yaml>"}
    - reseed_subscriber: {"imsi": "<14-15 digit IMSI>"}
    - rerun_capture: {"scenario": "<one of auth_failure,
      registration_reject, registration_timeout,
      pdu_session_reject_slice, pdu_session_reject_other,
      pdu_session_timeout, sbi_udm_timeout, sbi_nssf_reject,
      n4_upf_timeout>"}
    - observe_only: {}

    An action outside the vocabulary produces no proposal at all. Never
    write commands into the JSON — the commands are rendered by
    deterministic templates from the action and args."""
    incident: str = dspy.InputField(desc="the Alarm event description")
    root_cause: str = dspy.InputField(desc="the grounded root-cause "
                                           "narrative")
    proposal: str = dspy.OutputField(desc='JSON {"action", "args", '
                                          '"justification"}; action is '
                                          'one of the five vocabulary '
                                          'actions, args per the '
                                          'template')


def default_propose():
    """proposer(incident, root_cause) -> the selection dict, over
    ProposalSignature. Built lazily, like default_search: the Groq
    predictor builds on first use, so importing this module never
    requires GROQ_API_KEY or network (ADR-0002)."""

    def propose(incident: str, root_cause: str) -> dict:
        predictor = dspy.Predict(ProposalSignature)
        _groq_lm()
        result = predictor(incident=incident,
                           root_cause=root_cause or "(none)")
        return json.loads(result.proposal)

    return propose


def run_proposal(event: dict, root_cause: str, proposer=None) -> dict | None:
    """The Proposal node: run the proposer over the incident and the
    root-cause narrative and return the selection reduced to the three
    fields the Executor renders — {action, args, justification} — or
    None. ``proposer`` is the stub seam; the live default's Groq
    predictor is built lazily (ADR-0002). The action must name one of
    the fixed five-action vocabulary entries and the args a dict, with
    a non-empty justification; any invalid selection — and any proposer
    failure — yields None, so the record says so honestly instead of
    proposing something. The selection is rebuilt here from its own
    fields, so an LLM smuggling extra fields (commands, hashes) loses
    them: the commands come only from the Executor's templates."""
    try:
        if proposer is None:
            proposer = default_propose()
        selection = proposer(event.get("description", ""), root_cause)
    except Exception:
        # LLM failure modes are library-defined (missing key, quota,
        # schema); degrade like the specialists, never crash.
        return None
    if not isinstance(selection, dict):
        return None
    action = selection.get("action")
    args = selection.get("args")
    justification = selection.get("justification")
    if action not in ACTIONS or not isinstance(args, dict) \
            or not isinstance(justification, str) or not justification:
        return None
    if action == "observe_only" and args:
        # observe_only takes no args — the render rail skips it, so the
        # vocabulary check must reject bogus args here.
        return None
    return {"action": action, "args": dict(args),
            "justification": justification}
