"""ADR-0009: LangSmith tracing is opt-in, tree-shaped, and can never
break a run. These tests never pay LangSmith or Groq: the SDK's
RunTree is stubbed at import time and no LM is invoked (ADR-0002)."""

import json

import dspy
import pytest
from dspy.utils.callback_context import ACTIVE_CALL_ID

from triage import tracing
from triage.evidence import DecodedCapture
from triage.search import run_lats

GATE_ENV = {"LANGSMITH_TRACING": "true", "LANGCHAIN_API_KEY": "test-key",
            "LANGSMITH_API_KEY": "test-key",
            "LANGSMITH_PROJECT": "triage-dispatch"}


class StubRunTree:
    """Stand-in for langsmith.RunTree: records construction and posts."""

    created = []

    def __init__(self, **data):
        self.name = data.get("name")
        self.run_type = data.get("run_type")
        self.inputs = data.get("inputs")
        extra = data.get("extra") or {}
        # the SDK reads extra.metadata back as run.metadata
        self.metadata = extra.get("metadata", extra)
        self.parent_run = data.get("parent_run")
        self.outputs = None
        self.error = None
        self.posted = False
        StubRunTree.created.append(self)

    def end(self, *, outputs=None, error=None, **kwargs):
        self.outputs = outputs
        self.error = error

    def post(self, exclude_child_runs=True):
        self.posted = True


class ExpandSignature:
    pass


class FakePredict:
    signature = ExpandSignature


class FakeLM:
    model = "gpt-oss-120b"


@pytest.fixture
def tracing_on(monkeypatch):
    for key, value in GATE_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr("langsmith.RunTree", StubRunTree)
    saved = dspy.settings.get("callbacks", [])
    saved_source = tracing.SOURCE
    yield
    dspy.settings.configure(callbacks=saved)
    tracing.SOURCE = saved_source
    StubRunTree.created.clear()


@pytest.fixture
def tracing_off(monkeypatch):
    for key in GATE_ENV:
        monkeypatch.delenv(key, raising=False)


def test_disabled_by_default(tracing_off):
    assert not tracing.enabled()


def test_enabled_requires_both_flag_and_key(tracing_off, monkeypatch):
    monkeypatch.setenv("LANGSMITH_TRACING", "true")
    assert not tracing.enabled()
    monkeypatch.delenv("LANGSMITH_TRACING")
    monkeypatch.setenv("LANGCHAIN_API_KEY", "test-key")
    assert not tracing.enabled()
    monkeypatch.setenv("LANGSMITH_TRACING", "true")
    assert tracing.enabled()
    # the newer env name is accepted too (the SDK treats both as one)
    monkeypatch.delenv("LANGCHAIN_API_KEY")
    monkeypatch.setenv("LANGSMITH_API_KEY", "test-key")
    assert tracing.enabled()
    monkeypatch.setenv("LANGSMITH_TRACING", "false")
    assert not tracing.enabled()


def test_install_is_a_noop_when_disabled(tracing_off):
    tracing.install()
    assert not any(isinstance(cb, tracing.LangSmithCallback)
                   for cb in dspy.settings.get("callbacks", []))


def test_install_appends_once(tracing_on):
    tracing.install()
    callbacks = [cb for cb in dspy.settings.get("callbacks", [])
                 if isinstance(cb, tracing.LangSmithCallback)]
    assert len(callbacks) == 1
    first = callbacks[0]
    tracing.install()
    callbacks = [cb for cb in dspy.settings.get("callbacks", [])
                 if isinstance(cb, tracing.LangSmithCallback)]
    assert callbacks == [first]


def test_module_and_lm_calls_nest_under_the_module(tracing_on):
    cb = tracing.LangSmithCallback()
    cb.on_module_start("m1", FakePredict(), {"objective": "x"})
    token = ACTIVE_CALL_ID.set("m1")
    try:
        cb.on_lm_start("l1", FakeLM(), {"prompt": "..."})
        cb.on_lm_end("l1", {"message": "...",
                            "usage": {"total_tokens": 42}}, None)
    finally:
        ACTIVE_CALL_ID.reset(token)
    cb.on_module_end("m1", {"actions": "inspect 1"}, None)

    module_run, lm_run = StubRunTree.created
    assert module_run.name == "ExpandSignature"
    assert lm_run.name == "gpt-oss-120b"
    assert lm_run.run_type == "llm"
    assert lm_run.parent_run is module_run
    assert lm_run.outputs["usage"]["total_tokens"] == 42
    assert lm_run.posted and module_run.posted


def test_module_end_records_errors(tracing_on):
    cb = tracing.LangSmithCallback()
    cb.on_module_start("m1", FakePredict(), {"objective": "x"})
    cb.on_module_end("m1", None, RuntimeError("boom"))
    run = StubRunTree.created[-1]
    assert run.error is not None
    assert run.posted


def test_trace_run_scopes_dspy_calls_under_the_node(tracing_on):
    cb = tracing.LangSmithCallback()
    with tracing.trace_run("node.1.expand", incident="auth_failure"):
        cb.on_lm_start("l1", FakeLM(), {"prompt": "..."})
        cb.on_lm_end("l1", {"message": "ok"}, None)
    node_run, lm_run = StubRunTree.created
    assert node_run.name == "node.1.expand"
    assert node_run.metadata["incident"] == "auth_failure"
    assert lm_run.parent_run is node_run
    assert node_run.posted


def test_trace_run_is_a_noop_when_disabled(tracing_off):
    with tracing.trace_run("node.1.expand"):
        pass
    assert StubRunTree.created == []


def test_run_lats_posts_a_tree_shaped_trace(tracing_on):
    capture = DecodedCapture(n2={
        "kpis": {"procedure_failures": 1},
        "flows": [{
            "flow_id": 1, "ran_ue_ngap_id": 1, "amf_ue_ngap_id": 1,
            "partial": False,
            "messages": [
                {"ts": 1000.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                 "ngap": "InitialUEMessage", "kind": "initiatingMessage",
                 "nas": "5GMMRegistrationRequest", "nas_protected": False,
                 "nas_inner": None, "nas_cause": None, "unparsed": None},
                {"ts": 1001.5, "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1",
                 "ngap": "DownlinkNASTransport", "kind": "initiatingMessage",
                 "nas": "5GMMSecProtNASMessage", "nas_protected": True,
                 "nas_inner": "5GMMStatus",
                 "nas_cause": {"code": 91,
                               "name": "Payload was not forwarded"},
                 "unparsed": None}]}],
        "unassociated": []})

    episode = json.dumps({
        "incident_type": "registration_reject",
        "narrative": "The AMF echoed back cause 91.",
        "cited_evidence": [{"message": "5GMMStatus", "cause": 91,
                            "ts": 1001.5}]})

    def expand(objective, trajectory, n):
        if "Flow 1" in trajectory:
            return [f"finalize {episode}"]
        return ["inspect flow:1"]

    def evaluate(objective, trajectory):
        return {"reward": 1.0,
                "status": "complete" if "finalize" in trajectory
                          else "incomplete",
                "reflection": ""}

    result = run_lats(capture, {"flow_id": 1, "procedure": "registration",
                                "shape": "reject"},
                      expand=expand, evaluate=evaluate)
    assert result.episode is not None

    root = StubRunTree.created[0]
    names = [run.name for run in StubRunTree.created]
    assert root.name == "lats-search"
    assert root.metadata["procedure"] == "registration"
    assert root.outputs["episode"]["incident_type"] == "registration_reject"
    assert "node.1.expand" in names
    assert "node.2.execute" in names
    assert "node.2.evaluate" in names
    assert all(run.posted for run in StubRunTree.created)


def test_install_tags_runs_by_source(tracing_on):
    tracing.install(source="dispatch")
    cb = tracing.LangSmithCallback()
    cb.on_module_start("m1", FakePredict(), {"objective": "x"})
    cb.on_module_end("m1", {"actions": "..."}, None)
    assert StubRunTree.created[-1].metadata["source"] == "dispatch"
    with tracing.trace_run("lats-search"):
        pass
    assert StubRunTree.created[-1].metadata["source"] == "dispatch"


def test_tracing_failure_never_breaks_the_run(tracing_on, monkeypatch):
    class ExplodingRunTree(StubRunTree):
        def post(self, exclude_child_runs=True):
            raise RuntimeError("upload failed")

    monkeypatch.setattr("langsmith.RunTree", ExplodingRunTree)
    cb = tracing.LangSmithCallback()
    cb.on_module_start("m1", FakePredict(), {"objective": "x"})
    cb.on_module_end("m1", {"actions": "..."}, None)  # must not raise
    with tracing.trace_run("node.1.expand"):
        pass  # scope exit posts the node run; must not raise
