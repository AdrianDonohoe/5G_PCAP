# Observability is opt-in LangSmith tracing over dspy; MLflow is not used

On 2026-09-03 we added observability to the triage and dispatch projects. Both route every LLM call through dspy 3.3 (`dspy.LM` over Groq behind `dspy.Predict` modules), triage's LATS is a hand-rolled MCTS tree, and dispatch's pipeline spine is LangGraph. The open questions: LangSmith or MLflow for the dspy layer, and whether tracing is always-on or gated. ADR-0002's offline posture — lazy key-guarded construction, pytest never costs a call — must hold.

## Status

accepted

## Considered Options

- **MLflow's `dspy.autolog` for the dspy layer + LangSmith for the LangGraph spine**: zero custom code for the dspy side, but two dashboards, two key systems, and MLflow contributes nothing for LangGraph or for the tree shape of a LATS search. Rejected.
- **Always-on tracing whenever a key is present**: simplest configuration, but a dev shell with `LANGCHAIN_API_KEY` exported would make every pytest run emit network calls — ADR-0002's guarantee, silently broken. Rejected.
- **LangSmith everywhere via a custom dspy `BaseCallback` (chosen)**: one dashboard for both layers. dspy 3.3's callback API provides module and LM hooks, parent-child nesting via its active-call contextvar, and logs-and-swallows callback exceptions — so the shim is small, and the MCTS tree renders as nested runs by scoping node phases from the search code itself.

## Consequences

- **The tracing gate.** Tracing arms only when `LANGSMITH_TRACING` is truthy *and* a LangSmith key is set (`LANGCHAIN_API_KEY` or `LANGSMITH_API_KEY` — the SDK accepts both); otherwise no tracer is constructed and every scope is a no-op. A test asserts the default: disabled. Env-only, never committed (public repo).
- **One LangSmith project.** `LANGSMITH_PROJECT` names it (currently `triage-dispatch` for both codebases); runs are tagged by source (`triage` / `dispatch`) so one project stays filterable.
- **Tree-shaped traces.** One root run per search invocation (or per pipeline run in dispatch) → node-phase runs (`expand` / `execute` / `evaluate` / `backprop`) → dspy module and LM runs with inputs, outputs, and usage. Reasoning content is captured only if the dspy/Groq response path surfaces it — a nice-to-have, not a promise.
- **dispatch inherits triage's tracing.** dispatch already depends on triage as a path source, so its dspy calls trace through the same callback with no new machinery; the LangGraph spine's own hookup is a separate increment.
- **Tracing can never break a run.** dspy logs and swallows callback exceptions, and the callback additionally guards internally: observability failure degrades to absence, never to a crash.
