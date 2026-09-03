"""LATS search: MCTS over Actions, with LLM expand/evaluate steps.

ADR-0001: LATS is the central loop; the four tools
(inspect_decoded_evidence, query_topology, query_3gpp_spec,
query_episodic_memory) form its execute step's Action space. The structural
pattern (Node/Tree MCTS with injected expand/execute/evaluate modules)
follows raw_graphify/dspy_lats.py, minus MLflow and its Python-interpreter
execute module — here execute is deterministic tool dispatch, not an LLM.

Two deterministic parts keep the search honest, enforced in code rather
than trusted to the LLM:

- An Action parses to one of the four tools, or to `finalize <Episode
  JSON>`. Anything else is an unknown action.
- A node completes only when its finalize Action produces an Episode that
  validates against the Pydantic schema AND cites at least one Evidence
  grounded in the decode: a cited (message, ts) must match a decoded
  message (5e-4 s tolerance — observations print ts to 3 decimals), and a
  cited cause must equal the decoded one when present. That is ADR-0001's
  completeness bar ("a Hypothesis with no Evidence is not a valid
  Hypothesis") made mechanical.

The LLM steps (action proposals, trajectory scoring) default to
gpt-oss:120b via Groq (ADR-0002), built lazily so importing this module
never requires GROQ_API_KEY or network. Tests inject stub expand/evaluate
callables — the suite stays cheap, per ADR-0002.
"""

import math
import os
from dataclasses import dataclass, field

import dspy

from triage.evidence import DecodedCapture
from triage.memory import Episode, MemoryStore, query_episodic_memory
from triage.specrag import query_3gpp_spec
from triage.topology import query_topology
from triage import tracing

TOOLS = ("inspect", "topology", "spec", "memory", "finalize")

INCIDENT_TYPES = ["auth_failure", "registration_reject",
                  "registration_timeout", "pdu_session_reject_slice",
                  "pdu_session_reject_other", "pdu_session_timeout",
                  "pdu_session_rsp_timeout",
                  "sbi_udm_timeout", "sbi_nssf_reject",
                  "n4_upf_timeout"]

# dspy treats the first segment of the model string as its provider and
# sends the rest; Groq's own model IDs carry an "openai/" vendor prefix
# (openai/gpt-oss-120b), hence the doubled prefix. Verified against the
# live API: bare "gpt-oss-120b" 404s.
GROQ = ("openai/openai/gpt-oss-120b", "https://api.groq.com/openai/v1")


def parse_action(text: str) -> tuple[str, str]:
    """`TOOL rest` or `TOOL:rest` -> (tool, argument); lenient."""
    text = text.strip()
    if not text:
        return "", ""
    tool, sep, argument = text.partition(" ")
    if not sep:
        tool, sep, argument = text.partition(":")
    argument = argument.strip().strip("\"'").strip()
    if argument.startswith("[") and argument.endswith("]"):
        argument = argument[1:-1].strip()
    return tool.rstrip(":").lower(), argument


def _memory_kwargs(argument: str) -> dict:
    kwargs = {}
    for token in argument.split():
        if "=" not in token:
            continue
        key, _, value = token.partition("=")
        if key not in ("incident_type", "message", "cause", "limit"):
            continue
        if key in ("cause", "limit"):
            try:
                value = int(value)
            except ValueError:
                continue
        kwargs[key] = value
    return kwargs


def _message_inventory(capture: DecodedCapture) -> dict:
    """{(name, ts): cause code} for every decoded message in the capture."""
    inventory = {}
    for flow in capture.n2.get("flows") or []:
        for msg in flow.get("messages") or []:
            for name in (msg.get("ngap"), msg.get("nas"), msg.get("nas_inner")):
                if name and msg.get("ts") is not None:
                    cause = msg.get("nas_cause") or {}
                    inventory[(name, msg["ts"])] = cause.get("code")
    for msg in capture.n2.get("unassociated") or []:
        if msg.get("ngap") and msg.get("ts") is not None:
            inventory[(msg["ngap"], msg["ts"])] = None
    for msg in (capture.n4 or {}).get("messages") or []:
        if msg.get("name") and msg.get("ts") is not None:
            inventory[(msg["name"], msg["ts"])] = msg.get("cause_code")
    for msg in (capture.sbi or {}).get("messages") or []:
        if msg.get("name") and msg.get("ts") is not None:
            inventory[(msg["name"], msg["ts"])] = None
    return inventory


def grounded_evidence(capture: DecodedCapture, episode: Episode) -> list:
    """The cited evidence items that match a decoded message exactly."""
    inventory = _message_inventory(capture)
    grounded = []
    for ev in episode.cited_evidence:
        if ev.ts is None:
            continue
        for (name, ts), cause in inventory.items():
            if name == ev.message and abs(ts - ev.ts) < 5e-4:
                if ev.cause is not None and cause != ev.cause:
                    continue  # right message, wrong cause: ungrounded
                grounded.append(ev)
                break
    return grounded


def _finalize(capture: DecodedCapture, argument: str) -> tuple[str, Episode | None]:
    """Validate + ground a finalize Action's Episode JSON."""
    try:
        episode = Episode.model_validate_json(argument)
    except Exception as exc:
        return (f"finalize rejected: argument is not a valid Episode ({exc}). "
                f'Expected JSON: {{"incident_type": one of '
                f"{', '.join(INCIDENT_TYPES)}, \"narrative\": \"...\", "
                f'"cited_evidence": [{{"message": ..., "cause": ..., '
                f'"ts": ...}}]}}.', None)
    grounded = grounded_evidence(capture, episode)
    if not grounded:
        return ("finalize rejected: no cited evidence matches a decoded "
                "message. Cite message names and ts values exactly as shown "
                "in the observations.", None)
    return (f"finalize accepted: hypothesis grounded in {len(grounded)} "
            f"evidence item(s).", episode)


def execute_action(capture: DecodedCapture, action: str,
                   store: MemoryStore | None = None,
                   spec_index=None) -> tuple[str, Episode | None]:
    """The execute step: deterministic dispatch of one Action to one tool."""
    store = store or MemoryStore()
    tool, argument = parse_action(action)
    if tool == "inspect":
        from triage.evidence import inspect_decoded_evidence
        return inspect_decoded_evidence(capture, argument or "flows"), None
    if tool == "topology":
        return query_topology(capture.n2, capture.n4), None
    if tool == "spec":
        return query_3gpp_spec(argument or "", index=spec_index), None
    if tool == "memory":
        return query_episodic_memory(store, **_memory_kwargs(argument)), None
    if tool == "finalize":
        return _finalize(capture, argument)
    return (f'unknown action "{action}": expected one of {", ".join(TOOLS)}',
            None)


def _procedure_of(incident_type: str) -> str | None:
    """incident_type -> procedure label, for cross-incident similarity."""
    if incident_type.startswith(("auth", "registration")):
        return "Registration"
    if incident_type.startswith("pdu_session"):
        return "PDU Session"
    if incident_type == "sbi_udm_timeout":
        return "Registration"  # the hung auth-vector fetch stalls registration
    if incident_type == "sbi_nssf_reject":
        return "PDU Session"   # the slice consult happens during PDU session setup
    if incident_type == "n4_upf_timeout":
        return "PDU Session"   # the N4 view of PDU session establishment
    return None


def memory_context(store: MemoryStore, incident: dict, flow) -> str:
    """Relevant past Episodes for one Incident, to seed the search input.

    Retrieval is structural, not semantic (ADR-0002: structured lookup beats
    a vector DB at this store size). Similarity scores per Episode: 3 per
    shared cause code, 1 per shared message name, 2 for the same procedure;
    Episodes scoring below 2 are not relevant. Most relevant first, top 3.
    """
    episodes = store.load()
    if not episodes:
        return ""
    procedure = incident.get("procedure")
    names = set()
    causes = set()
    for msg in (flow or {}).get("messages") or []:
        for key in ("nas_inner", "nas", "ngap"):
            if msg.get(key):
                names.add(msg[key])
        cause = (msg.get("nas_cause") or {}).get("code")
        if cause:
            causes.add(cause)
    scored = []
    for ep in episodes:
        cited = ep.cited_evidence
        shared_causes = {ev.cause for ev in cited
                         if ev.cause is not None} & causes
        shared_names = {ev.message for ev in cited} & names
        same_procedure = procedure is not None and \
            _procedure_of(ep.incident_type) == procedure
        score = (3 * len(shared_causes) + len(shared_names)
                 + (2 if same_procedure else 0))
        if score >= 2:
            scored.append((score, ep))
    if not scored:
        return ""
    scored.sort(key=lambda pair: (pair[0], pair[1].created_at), reverse=True)
    lines = ["Past similar incidents retrieved from episodic memory "
             f"({len(scored)} of {len(episodes)} Episode(s)):"]
    for i, (_, ep) in enumerate(scored[:3], 1):
        cited = "; ".join(
            ev.message
            + (f" cause={ev.cause}" if ev.cause is not None else "")
            for ev in ep.cited_evidence)
        lines.append(f"[{i}] {ep.incident_type}  {ep.created_at.isoformat()}")
        lines.append(f"    {ep.narrative}")
        lines.append(f"    cited: {cited}")
    return "\n".join(lines)


def objective_text(incident: dict, memory: str = "") -> str:
    """The objective the search runs against, from the Incident description
    plus (optionally) relevant past Episodes retrieved from memory."""
    if incident.get("flow_id") is not None \
            and incident.get("plane") not in ("sbi", "n4"):
        # Neutral phrasing: a mid-flow cause-bearing message (e.g. a 5GMM
        # STATUS) can make an incident while the procedure records still
        # read accept -- claiming "the procedure failed" would prime a
        # contradiction with the decode the search is about to inspect.
        lines = [f"Explain the failure incident in flow "
                 f"{incident['flow_id']} ({incident['procedure']}) in this "
                 f"decoded 5G capture."]
    else:  # SBI/N4 incidents: no N2 flow of their own; the procedure IS the
        # plane's unit. A joined incident keeps that focus and adds one
        # flow clause pointing at the correlated flow's messages.
        plane = {"sbi": "SBI", "n4": "N4"}.get(incident.get("plane"), "SBI")
        lines = [f"Explain why the {incident['procedure']} procedure failed "
                 f"on the {plane} plane in this decoded 5G capture."]
        if incident.get("flow_id") is not None:
            lines.append(f"Correlated flow: this procedure is part of flow "
                         f"{incident['flow_id']}'s signaling — inspect "
                         f"flow:{incident['flow_id']} alongside the "
                         f"{plane} handles.")
    if incident.get("shape"):
        lines.append(f"Failure shape: {incident['shape']}.")
    if incident.get("shape") == "no terminal message (timeout)":
        lines.append("There is no reject message and no terminal procedure "
                     "record to find: the failure is an absence. Inspect "
                     "what did arrive, then finalize on that evidence "
                     "instead of waiting for a reject that never comes.")
    if incident.get("detail"):
        lines.append(f"Incident detail: {incident['detail']}.")
    if memory:
        lines.append(memory)
        lines.append("These memory entries are context only: cited_evidence "
                     "must still cite messages decoded in THIS capture.")
    lines.append("Take one action per step. Actions: "
                 '"inspect <handle>" (kpis, flows, flow:<id>, flow:<id>:<i>, '
                 "unassociated[:<i>], n4[:<i>], sbi[:<i>]), \"topology\", "
                 '"spec <question>", "memory [incident_type=... message=... '
                 'cause=...]", or "finalize <episode JSON>". '
                 "Finish with finalize once the evidence supports a root "
                 "cause; its JSON must have incident_type (one of "
                 f"{', '.join(INCIDENT_TYPES)}), narrative, and "
                 "cited_evidence.")
    return "\n".join(lines)


def _field(result, name: str, default):
    if isinstance(result, dict):
        return result.get(name, default)
    return getattr(result, name, default)


def _trajectory_text(node) -> str:
    pairs = node.trajectory()
    if not pairs:
        return ""
    return "\n".join(f"action: {a}\nobservation: {o}" for a, o in pairs)


@dataclass
class Node:
    action: str
    depth: int
    parent: "Node | None" = None
    observation: str | None = None
    episode: Episode | None = None
    children: list = field(default_factory=list)
    value: float = 0.0
    reward: float = 0.0
    visits: int = 0
    status: str = "incomplete"  # complete | failed | incomplete

    def trajectory(self) -> list[tuple[str, str]]:
        pairs = self.parent.trajectory() if self.parent else []
        if not self.action:  # the root node contributes nothing
            return pairs
        return pairs + [(self.action, self.observation or "")]

    def backprop(self, reward: float) -> None:
        self.visits += 1
        self.value += (reward - self.value) / self.visits
        if self.parent:
            self.parent.backprop(reward)


def _ucb(parent: Node, child: Node, C: float) -> float:
    if child.visits == 0:
        return math.inf
    if child.status == "failed":
        return 0.0
    return child.value / child.visits + \
        C * math.sqrt(math.log(parent.visits) / child.visits)


@dataclass
class SearchResult:
    episode: Episode | None
    reward: float
    trajectory: list
    rollouts: int


class Tree:
    """The MCTS tree: rollouts of expand -> execute -> evaluate -> backprop.

    expand(objective, trajectory, n) -> list of Action strings; evaluate
    (objective, trajectory) -> result with reward/status/reflection fields.
    """

    def __init__(self, expand, evaluate, execute, C: float = 1.4,
                 max_depth: int = 3):
        self.expand = expand
        self.evaluate = evaluate
        self.execute = execute
        self.C = C
        self.max_depth = max_depth
        self.exit_on_complete = True

    def _observe_and_evaluate(self, child: Node, objective: str) -> None:
        with tracing.trace_run(f"node.{child.depth}.execute",
                               action=child.action):
            observation, episode = self.execute(child.action)
        child.observation = observation
        child.episode = episode
        try:
            with tracing.trace_run(f"node.{child.depth}.evaluate",
                                   action=child.action):
                result = self.evaluate(objective, _trajectory_text(child))
            reward = float(_field(result, "reward", 0.0))
            status = str(_field(result, "status", "incomplete"))
        except Exception:
            # The trace shows the failure on the evaluate run; the tree
            # degrades as before.
            reward, status = 0.0, "failed"
        child.reward = reward
        # Completeness is deterministic: a grounded finalize completes the
        # node even if the LLM's status disagrees; the LLM only scores.
        child.status = ("complete" if episode is not None else
                        "failed" if status == "failed" else "incomplete")
        child.backprop(reward)

    def _rollout(self, node: Node, objective: str, n_branches: int) -> None:
        if node.status == "failed" or node.depth > self.max_depth:
            node.status = "failed"
            return
        if not node.children:
            try:
                with tracing.trace_run(f"node.{node.depth}.expand"):
                    actions = self.expand(objective, _trajectory_text(node),
                                          n_branches)
            except Exception:
                actions = []
            seen = set()
            for action in actions:
                if action and action not in seen:
                    seen.add(action)
                    node.children.append(
                        Node(action=action, depth=node.depth + 1,
                             parent=node))
            if not node.children:
                node.status = "failed"
                return
            for child in node.children:
                self._observe_and_evaluate(child, objective)
                if self.exit_on_complete and child.episode is not None:
                    return
            return
        best = max(node.children, key=lambda c: _ucb(node, c, self.C))
        self._rollout(best, objective, n_branches)

    def _completed(self, node: Node, acc: list) -> None:
        if node.episode is not None:
            acc.append(node)
        for child in node.children:
            self._completed(child, acc)

    def _best_partial(self, root: Node) -> Node | None:
        """The highest-reward evaluated node: the best trajectory so far,
        completed or not."""
        nodes = []
        stack = list(root.children)
        while stack:
            node = stack.pop()
            if node.observation is not None:
                nodes.append(node)
            stack.extend(node.children)
        return max(nodes, key=lambda n: n.reward) if nodes else None

    def _force_finalize(self, root: Node, objective: str) -> list:
        """One forced finalize on the best partial trajectory.

        Search variance can leave no completed node (no finalize was
        proposed, or every proposal was rejected as ungrounded); an
        incident the search did cover deserves a grounded hypothesis over
        an empty report section. Still a real finalize: grounding applies
        and the reward comes from evaluating the final trajectory.
        """
        best = self._best_partial(root)
        if best is None:
            return []
        try:
            with tracing.trace_run(f"node.{best.depth}.expand",
                                   action="finalize"):
                actions = self.expand(
                    objective,
                    _trajectory_text(best) +
                    "\nPropose exactly one finalize action from this "
                    "trajectory: it must end the search now.", 1)
        except Exception:
            return []
        for action in actions:
            if action and action.strip().startswith("finalize"):
                break
        else:
            return []
        child = Node(action=action.strip(), depth=best.depth + 1,
                     parent=best)
        best.children.append(child)
        self._observe_and_evaluate(child, objective)
        return [child] if child.episode is not None else []

    def run(self, objective: str, n_branches: int = 3,
            max_rollouts: int = 10, exit_on_complete: bool = True
            ) -> SearchResult:
        self.exit_on_complete = exit_on_complete
        root = Node(action="", depth=1)
        for rollouts in range(1, max_rollouts + 1):
            self._rollout(root, objective, n_branches)
            done = []
            self._completed(root, done)
            if exit_on_complete and done:
                break
        done = []
        self._completed(root, done)
        if not done:
            done = self._force_finalize(root, objective)
        best = max(done, key=lambda n: n.reward) if done else None
        return SearchResult(episode=best.episode if best else None,
                            reward=best.reward if best else 0.0,
                            trajectory=best.trajectory() if best else [],
                            rollouts=rollouts)


class ExpandSignature(dspy.Signature):
    """You are triaging why a 5G Registration or PDU Session procedure
    failed, using a decoded capture. Propose n alternative next actions,
    one per line, in the format TOOL ARGUMENT.

    Tools: inspect <handle> (handles: kpis, flows, flow:<id>, flow:<id>:<i>,
    unassociated[:<i>], n4[:<i>], sbi[:<i>]), topology, spec <question>,
    memory [incident_type=... message=... cause=...], or finalize <episode
    JSON>. finalize is the ONLY way to end the search: propose it as soon
    as the trajectory contains the failure's key evidence — a reject
    message with its cause code, a partial flow whose terminal message
    never arrived, or — for a timeout shape — the last messages that did
    arrive (there is no reject to wait for). finalize JSON template (copy
    message names, cause codes and ts values EXACTLY as shown in the
    observations):

    {"incident_type": "<one of auth_failure, registration_reject,
    registration_timeout, pdu_session_reject_slice,
    pdu_session_reject_other, pdu_session_timeout,
    pdu_session_rsp_timeout, sbi_udm_timeout,
    sbi_nssf_reject, n4_upf_timeout>",
    "narrative": "<one-sentence root-cause explanation>",
    "cited_evidence": [{"message": "<decoded message name>",
    "cause": <code or null>, "ts": <timestamp from observation>}]}

    A cause-bearing reject is usually a terminal symptom, not the root
    cause: if the trajectory shows an earlier exceptional message (e.g.
    5GMMAuthenticationFailure), the narrative must explain THAT and cite
    it as evidence too. Pick the incident_type from the wire shape, not
    from cause-name keywords: auth_failure when an AuthenticationFailure
    message appears (a Registration Reject that follows it is the
    terminal symptom of the same failure: the type is auth_failure and
    the narrative chains the AuthenticationFailure to the reject);
    registration_reject for a Registration Reject with no earlier
    AuthenticationFailure; registration_timeout when no Registration
    terminal ever arrived;
    pdu_session_reject_slice for 5GMM STATUS cause 91 (DNN not supported
    in the slice) — a reject whose cause NAME merely mentions "slice" is
    NOT the slice type. When the flow's procedure records still read
    accept, the STATUS bounced ONE request (a different slice/DNN than
    the completed session): the narrative must say the STATUS bounced
    that request — never "the PDU Session was rejected" or "failed",
    which the accept records contradict; pdu_session_reject_other for
    any other PDU Session REJECT (e.g. cause 67); pdu_session_timeout when NO reject
    exists but cause 90 "Payload was not forwarded" echoes on the UE's
    repeated request with multi-second gaps;
    pdu_session_rsp_timeout is pdu_session_timeout's egress twin: the N2
    shape is the same cause 90 echo, but the SBI plane shows the
    sm-contexts create unanswered (a timeout procedure joined to the
    flow) where pdu_session_timeout's create never reaches the SMF and
    leaves no SBI message at all — cite the unanswered create. On the SBI plane: a request
    answered with HTTP status >= 400 is an explicit reject (cite the
    service name and ts; the status belongs in the narrative, cause is
    null) — sbi_nssf_reject when the Nnssf_NSSelection consult is
    rejected (e.g. 403); an unanswered SBI request is a timeout, and
    sbi_udm_timeout is the type when a Nudm_* request (e.g. AUSF's
    Nudm_UEAuthentication) never gets a response. On the N4 plane:
    n4_upf_timeout is the type when a session-management PFCP procedure
    (e.g. session_establishment) times out — cite the unanswered PFCP
    Session Establishment Request(s) (the SMF retransmits every ~2.5 s,
    the burst is the timeout's signature, and the listing marks later
    sends (retransmit)) with cause null and the ts of the first,
    unmarked send; a PFCP response carrying a non-accept Cause is an
    explicit reject and the numeric cause belongs in the cited evidence's
    cause field. Never repeat an action
    already in the trajectory, and prefer finalize over more
    evidence-gathering once the failure's key evidence has been
    observed."""
    objective: str = dspy.InputField(desc="The failure to explain")
    trajectory: str = dspy.InputField(
        desc="Previous actions and their observations; empty if none")
    n: int = dspy.InputField(desc="Number of alternative actions to propose")
    actions: str = dspy.OutputField(desc="One action per line, nothing else")


class EvaluateSignature(dspy.Signature):
    """Score how well this trajectory explains the objective's failure.
    The trajectory is complete when its finalize action produced a grounded
    root-cause hypothesis."""
    objective: str = dspy.InputField(desc="The failure to explain")
    trajectory: str = dspy.InputField(desc="Actions and observations so far")
    reward: float = dspy.OutputField(
        desc="0.0 to 1.0: how far the trajectory supports the ROOT cause "
             "(why the procedure failed, e.g. an authentication failure), "
             "not just the terminal reject cause")
    status: str = dspy.OutputField(
        desc="one of: complete, failed, incomplete")
    reflection: str = dspy.OutputField(
        desc="One sentence: what the trajectory established or lacks")


def _groq_lm():
    key = os.environ.get("GROQ_API_KEY")
    if not key:
        raise RuntimeError("GROQ_API_KEY is not set (ADR-0002: no local "
                           "model fallback)")
    # Groq serves an OpenAI-compatible API; this route works without a
    # dspy Groq provider and keeps the model swappable (ADR-0002).
    # max_tokens: trajectory transcripts plus finalize JSON overflow the
    # 4096 default and DSPy silently truncates the response.
    lm = dspy.LM(GROQ[0], api_base=GROQ[1], api_key=key, cache=False,
                 max_tokens=8192)
    dspy.configure(lm=lm)
    # ADR-0009: arm LangSmith tracing if the gate is on (idempotent no-op
    # otherwise); the module and LM calls below then trace as tree-shaped
    # runs. install() lives here so importing search.py never touches it.
    tracing.install()
    return lm


def default_expand():
    """expand(objective, trajectory, n) -> list of Action strings."""
    predictor = dspy.Predict(ExpandSignature)
    _groq_lm()

    def expand(objective: str, trajectory: str, n: int) -> list[str]:
        result = predictor(objective=objective,
                           trajectory=trajectory or "(none yet)", n=n)
        return [line.strip() for line in result.actions.splitlines()
                if line.strip()][:n]
    return expand


def default_evaluate():
    """evaluate(objective, trajectory) -> reward/status/reflection."""
    predictor = dspy.Predict(EvaluateSignature)
    _groq_lm()
    return lambda objective, trajectory: predictor(
        objective=objective, trajectory=trajectory or "(none yet)")


def run_lats(capture: DecodedCapture, incident: dict,
             store: MemoryStore | None = None, spec_index=None,
             n_branches: int = 3, max_rollouts: int = 10,
             max_depth: int = 3, expand=None, evaluate=None,
             C: float = 1.4) -> SearchResult:
    """Run the LATS search for one Incident; returns the best Hypothesis.

    Raises RuntimeError when expand/evaluate default to the Groq-backed
    predictors and GROQ_API_KEY is unset (ADR-0002: no local fallback).
    Mid-search LLM failures degrade inside the tree instead.
    """
    store = store or MemoryStore()
    expand = expand or default_expand()
    evaluate = evaluate or default_evaluate()
    # Seed the objective with relevant past Episodes (deterministic
    # retrieval; the LLM may still call the memory tool mid-search).
    flow = next((f for f in capture.n2.get("flows") or []
                 if f.get("flow_id") == incident.get("flow_id")), None)
    memory = memory_context(store, incident, flow)
    tree = Tree(expand, evaluate,
                execute=lambda action: execute_action(capture, action,
                                                      store, spec_index),
                C=C, max_depth=max_depth)
    objective = objective_text(incident, memory=memory)
    # ADR-0009: with the tracing gate on, this is the Trace's root run and
    # the node phases inside tree.run() become its children.
    with tracing.trace_run(
            "lats-search",
            procedure=incident.get("procedure"),
            shape=incident.get("shape"),
            flow_id=incident.get("flow_id"),
            objective=objective) as run:
        result = tree.run(objective, n_branches=n_branches,
                          max_rollouts=max_rollouts)
        if run is not None and result.episode is not None:
            run.end(outputs={"episode": result.episode.model_dump()})
    return result
