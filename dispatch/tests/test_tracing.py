"""ADR-0009 in dispatch: the LangGraph spine and the dspy seam arm tracing
only when the gate is on, and dispatch's dspy runs are tagged by source.
No LangSmith call and no Groq call here — the tracer class is stubbed and
dspy.LM construction never dials the API (ADR-0002)."""

import dspy
import pytest

from dispatch import graph as graph_mod
from dispatch.log import _groq_lm
from triage import tracing


@pytest.fixture
def gate_env(monkeypatch):
    monkeypatch.setenv("LANGSMITH_TRACING", "true")
    monkeypatch.setenv("LANGCHAIN_API_KEY", "test-key")
    monkeypatch.setenv("LANGSMITH_PROJECT", "triage-dispatch")
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    saved = dspy.settings.get("callbacks", [])
    saved_source = tracing.SOURCE
    yield
    dspy.settings.configure(callbacks=saved)
    tracing.SOURCE = saved_source


def test_config_has_no_tracer_by_default(monkeypatch):
    for key in ("LANGSMITH_TRACING", "LANGCHAIN_API_KEY",
                "LANGSMITH_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    assert "callbacks" not in graph_mod._config("incident-1")


def test_config_attaches_tracer_when_armed(monkeypatch, gate_env):
    class StubTracer:
        pass

    monkeypatch.setattr("langchain_core.tracers.langchain.LangChainTracer",
                        StubTracer)
    config = graph_mod._config("incident-1")
    assert len(config["callbacks"]) == 1
    assert isinstance(config["callbacks"][0], StubTracer)


def test_groq_lm_installs_tracing_tagged_dispatch(gate_env):
    _groq_lm()
    callbacks = [cb for cb in dspy.settings.get("callbacks", [])
                 if isinstance(cb, tracing.LangSmithCallback)]
    assert len(callbacks) == 1
    assert tracing.SOURCE == "dispatch"
