"""LangSmith tracing for the LATS search (ADR-0009).

The gate is explicit: tracing arms only when LANGSMITH_TRACING is a
truthy flag *and* LANGCHAIN_API_KEY is set; otherwise enabled() is
False, install() does nothing, and trace_run() yields without
constructing anything — ADR-0002's offline posture holds and pytest
never pays LangSmith.

The LangSmithCallback fans dspy module and LM calls into RunTree runs,
parented by dspy's active-call nesting first and by the enclosing
trace_run scope second, so a trace reads like the search tree. Upload
failures are swallowed: observability degrades to absence, never to a
crash. The SDK is imported lazily, only when tracing is armed.
"""

import contextvars
import logging
import os
from contextlib import contextmanager

from dspy.utils.callback import BaseCallback
from dspy.utils.callback_context import ACTIVE_CALL_ID

logger = logging.getLogger(__name__)

SOURCE = "triage"  # ADR-0009: runs are tagged by source for filtering
_TRUTHY = ("1", "true", "yes", "on")
_PARENT_RUN = contextvars.ContextVar("tracing_parent_run", default=None)


def enabled() -> bool:
    return (os.environ.get("LANGSMITH_TRACING", "").lower() in _TRUTHY
            and bool(os.environ.get("LANGCHAIN_API_KEY")))


def _run_tree(**data):
    from langsmith import RunTree
    return RunTree(**data)


def _post(run) -> None:
    try:
        run.post()
    except Exception:
        logger.warning("LangSmith upload failed; continuing untraced",
                       exc_info=True)


class LangSmithCallback(BaseCallback):
    """Fans dspy module and LM calls into LangSmith runs."""

    def __init__(self):
        self._runs = {}

    def _start(self, call_id, name, run_type, inputs):
        run = _run_tree(name=name, run_type=run_type, inputs=inputs,
                        metadata={"source": SOURCE},
                        parent_run=self._parent())
        self._runs[call_id] = run

    def _parent(self):
        # dspy nesting (the enclosing module call) wins; otherwise the
        # enclosing trace_run scope.
        return self._runs.get(ACTIVE_CALL_ID.get()) or _PARENT_RUN.get()

    def _end(self, call_id, outputs, exception):
        run = self._runs.pop(call_id, None)
        if run is None:
            return
        try:
            run.end(outputs=outputs,
                    error=str(exception) if exception else None)
            _post(run)
        except Exception:
            logger.warning("LangSmith callback failed; continuing untraced",
                           exc_info=True)

    def on_module_start(self, call_id, instance, inputs):
        signature = getattr(getattr(instance, "signature", None),
                            "__name__", type(instance).__name__)
        self._start(call_id, signature, "chain", inputs)

    def on_module_end(self, call_id, outputs, exception=None):
        self._end(call_id, outputs, exception)

    def on_lm_start(self, call_id, instance, inputs):
        self._start(call_id, getattr(instance, "model", "lm"), "llm", inputs)

    def on_lm_end(self, call_id, outputs, exception=None):
        self._end(call_id, outputs, exception)


def install(source: str = SOURCE) -> None:
    """Append the callback to dspy's settings once; no-op when disabled.

    `source` tags the runs this process posts (ADR-0009: triage and
    dispatch share one LangSmith project and are told apart by source).
    The callback reads SOURCE when a run starts, so it applies to runs
    the existing callback fans out too."""
    if not enabled():
        return
    global SOURCE
    SOURCE = source
    import dspy
    callbacks = list(dspy.settings.get("callbacks", []))
    if any(isinstance(cb, LangSmithCallback) for cb in callbacks):
        return
    dspy.settings.configure(callbacks=callbacks + [LangSmithCallback()])


@contextmanager
def trace_run(name: str, **metadata):
    """One scope per search-node phase (or the root search). dspy module
    and LM calls created inside the scope nest under it. No-op when
    disabled. Yields the run so callers may set outputs via run.end()."""
    if not enabled():
        yield
        return
    run = _run_tree(name=name, run_type="chain", inputs=dict(metadata),
                    metadata={"source": SOURCE, **metadata},
                    parent_run=_PARENT_RUN.get())
    token = _PARENT_RUN.set(run)
    try:
        yield run
    except Exception as e:
        run.end(error=str(e))
        _post(run)
        raise
    else:
        if run.outputs is None:
            run.end(outputs={})
        _post(run)
    finally:
        _PARENT_RUN.reset(token)
