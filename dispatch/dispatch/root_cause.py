"""The root-cause investigation: a LATS-style search at the Dispatcher
layer over the multi-source evidence inventory.

triage's Tree and signatures are imported as a library — dispatch is the
only context that depends on triage's Python API (ADR-0001); the expand
signature is subclassed to rewrite its prompt for the Dispatcher's
action space — while the execute step is the Dispatcher's own: `inspect`
renders the correlated inventory (pcap, log and KPI items with their
citations and the correlation links) and `finalize` accepts an episode
whose citations must name inventory items exactly, extending the
grounding discipline across sources. The winning trajectory's narrative
becomes the record's root-cause section.

The search is the stub seam: `run_root_cause` takes an injected search
callable (tests pass a canned search or a real Tree with stub
expand/evaluate steps — the spec's stub-injected Tree pattern); the live
search's expand/evaluate predictors are lazy Groq calls built on demand,
so importing this module never requires GROQ_API_KEY or network
(ADR-0002). Any failure yields "" — never an invented root cause."""

import json

import dspy

from triage.search import (ExpandSignature as TriageExpandSignature,
                           EvaluateSignature, Tree, parse_action)
from .log import GROQ, _groq_lm
from .memory import memory_context

# The Dispatcher's action vocabulary: triage's tools are decode-specific
# (topology, spec, memory), only the search discipline carries over.
TOOLS = ("inspect", "finalize")


# triage's expand prompt describes its decode tools and finalize schema,
# which the Dispatcher's execute step does not offer; the subclass
# rewrites the prompt (dspy takes the class docstring) while importing
# the signature — triage's class is never mutated, per ADR-0001.
class ExpandSignature(TriageExpandSignature):
    """You are explaining why a 5G network incident happened, using the
    evidence inventory in the objective. Propose n alternative next
    actions, one per line, in the format TOOL ARGUMENT.

    Tools: inspect (re-lists the evidence inventory and its correlation
    links) or finalize <episode JSON>. finalize is the ONLY way to end
    the search: propose it as soon as the trajectory contains the
    failure's key evidence — at least one evidence item whose citation
    is copied EXACTLY as shown in the observations. finalize JSON
    template (copy citations EXACTLY as shown in the observations):

    {"narrative": "<one-sentence root-cause explanation>",
    "cited_evidence": [{"citation": "<exact citation from the inventory>"}]}

    The narrative must explain the failure through the cited items
    across the sources (pcap, log, KPI); a finalize whose citations do
    not name inventory items exactly is rejected. Never repeat an
    action already in the trajectory, and prefer finalize over more
    evidence-gathering once the key evidence has been observed."""


def inspect_observation(evidence: list, links: list) -> str:
    """The `inspect` observation: the inventory rendered deterministically
    — one line per evidence item with its source, kind, entry, keys and
    exact citation, then the correlation links. The agent cites items by
    their citation; the indices are for reading only."""
    lines = [f"Evidence inventory ({len(evidence)} item(s)):"]
    for index, item in enumerate(evidence, 1):
        keys = ", ".join(f"{k}={v}" for k, v in item.get("keys", {}).items())
        key_part = f" (keys: {keys})" if keys else ""
        citation = item["citation"]
        # A log item's looked-up line rides along so the agent can read
        # the evidence; the citation token itself stays copyable-exact.
        if item.get("line"):
            citation = f"{citation} (line: {item['line']})"
        lines.append(f"[{index}] {item['source']} {item['kind']}: "
                     f"{item['entry']}{key_part} — "
                     f"citation: {citation}")
    if not evidence:
        lines.append("- (no evidence)")
    if links:
        for edge in links:
            lines.append(f"[{edge['a'] + 1}] ↔ [{edge['b'] + 1}] via "
                         f"{edge['key']}={edge['value']}")
    else:
        lines.append("- no links")
    return "\n".join(lines)


def objective_text(event: dict, evidence: list, links: list) -> str:
    """The search objective, built from the event and the Correlation
    graph: the incident description plus the correlated inventory, naming
    evidence from all three sources with their exact citations."""
    return (
        f"Explain the failure incident: {event.get('description', '')}\n\n"
        f"{inspect_observation(evidence, links)}\n\n"
        "Investigate with `inspect` to re-read the inventory, then "
        "`finalize` with a JSON episode {\"narrative\": \"...\", "
        "\"cited_evidence\": [{\"citation\": \"...\"}]} whose citations "
        "name inventory items exactly as shown."
    )


def grounded_episode(episode, evidence: list) -> dict | None:
    """Ground an episode against the inventory, or reject it. Cited claims
    whose citation names an inventory item exactly are kept; fabricated
    citations are dropped, and at least one grounded claim is required
    (the completeness bar, extended across pcap, log and KPI citations).
    The narrative must be a non-empty string. The node re-grounds the
    search's episode with this same check, so an injected fake is
    verified the same way as the live path."""
    if not isinstance(episode, dict):
        return None
    narrative = episode.get("narrative")
    cited = episode.get("cited_evidence")
    if not isinstance(narrative, str) or not narrative \
            or not isinstance(cited, list):
        return None
    citations = {item.get("citation") for item in evidence}
    kept = [claim for claim in cited
            if isinstance(claim, dict)
            and isinstance(claim.get("citation"), str)
            and claim["citation"] in citations]
    if not kept:
        return None
    return {"narrative": narrative, "cited_evidence": kept}


def _finalize(evidence: list, argument: str) -> tuple[str, dict | None]:
    """`finalize`: parse the episode JSON and ground it against the
    inventory. Grounded finalize returns the episode (the tree completes
    the node on it, however the evaluator scores); ungrounded finalize is
    rejected with the reason, mirroring triage's rejection messages."""
    try:
        episode = json.loads(argument)
    except (json.JSONDecodeError, TypeError):
        return ('finalize rejected: the argument is not valid JSON. '
                'Expected {"narrative": "...", "cited_evidence": '
                '[{"citation": "..."}]}.', None)
    grounded = grounded_episode(episode, evidence)
    if grounded is None:
        return ("finalize rejected: no cited evidence names an inventory "
                "item. Cite citations exactly as shown in the inventory.",
                None)
    return (f"finalize accepted: hypothesis grounded in "
            f"{len(grounded['cited_evidence'])} evidence item(s).",
            grounded)


def make_execute(evidence: list, links: list):
    """execute(action) -> (observation, episode-or-None): the Dispatcher's
    deterministic action dispatch. triage's Tree calls this; triage's own
    execute_action is decode-specific, so only the machinery is shared."""

    def execute(action: str) -> tuple[str, dict | None]:
        tool, argument = parse_action(action)
        if tool == "inspect":
            return inspect_observation(evidence, links), None
        if tool == "finalize":
            return _finalize(evidence, argument)
        return (f"unknown action \"{action}\": expected one of "
                f"{', '.join(TOOLS)}", None)

    return execute


def default_expand():
    """expand(objective, trajectory, n) -> list of action strings, over
    triage's ExpandSignature. Built lazily: importing this module never
    requires GROQ_API_KEY or network (ADR-0002)."""
    predictor = dspy.Predict(ExpandSignature)
    _groq_lm()

    def expand(objective: str, trajectory: str, n: int) -> list[str]:
        result = predictor(objective=objective,
                           trajectory=trajectory or "(none yet)", n=n)
        return [line.strip() for line in result.actions.splitlines()
                if line.strip()][:n]

    return expand


def default_evaluate():
    """evaluate(objective, trajectory) -> reward/status/reflection, over
    triage's EvaluateSignature. Built lazily, like default_expand."""
    predictor = dspy.Predict(EvaluateSignature)
    _groq_lm()
    return lambda objective, trajectory: predictor(
        objective=objective, trajectory=trajectory or "(none yet)")


def default_search(evidence: list, links: list):
    """search(objective) -> the winning episode dict or None: the live
    search — triage's Tree over the imported signatures with the
    Dispatcher's execute step. Built lazily, like default_expand."""

    def search(objective: str) -> dict | None:
        tree = Tree(expand=default_expand(), evaluate=default_evaluate(),
                    execute=make_execute(evidence, links))
        return tree.run(objective).episode

    return search


def run_root_cause(event: dict, evidence: list, links: list,
                   search=None, episodes=None) -> str:
    """The Investigate node: run the root-cause search over the correlated
    multi-source inventory and return the winning trajectory's narrative,
    grounded. ``search`` is the stub seam; the live search is the LATS
    Tree whose Groq predictors are built lazily (ADR-0002). Any failure
    yields "" — the record renders the honest fallback, never an invented
    root cause. The search's episode is re-grounded here, so injected
    fakes are verified the same way as the live path.

    ``episodes`` is the Episode store seam (spec #33): when present, past
    similar Episodes seed the objective ahead of the incident description
    (structured lookup — no embeddings, no API calls); absent means
    today's objective exactly."""
    if not evidence:
        return ""
    objective = objective_text(event, evidence, links)
    if episodes is not None:
        context = memory_context(episodes, event, evidence)
        if context:
            objective = context + "\n\n" + objective
    try:
        if search is None:
            search = default_search(evidence, links)
        episode = search(objective)
    except Exception:
        # LLM failure modes are library-defined (missing key, quota,
        # schema); degrade like the specialists, never crash.
        return ""
    episode = grounded_episode(episode, evidence)
    return episode["narrative"] if episode else ""
