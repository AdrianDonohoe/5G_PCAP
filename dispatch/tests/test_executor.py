"""Executor guard rails: fixed vocabulary, deterministic templates, dry-run
by default, hash verification, and sandbox containment."""

import pytest

from dispatch.executor import Executor, render, proposal_hash


COMPOSE = """services:
  amf:
    image: oai-amf
  upf:
    image: oai-upf
  mongo:
    image: mongo
"""


@pytest.fixture
def sandbox(tmp_path):
    (tmp_path / "core").mkdir()
    (tmp_path / "core" / "docker-compose.yml").write_text(COMPOSE)
    return tmp_path


@pytest.fixture
def runner():
    calls = []

    def fake(cmd, **kw):
        calls.append(cmd)
        return 0

    fake.calls = calls
    return fake


def test_render_restart_nf(sandbox):
    cmd = render("restart_nf", {"nf": "upf"}, sandbox)
    assert cmd == [f"docker compose --project-directory {sandbox}/core restart upf"]


def test_render_refuses_unknown_action(sandbox):
    with pytest.raises(ValueError, match="vocabulary"):
        render("rm_rf_everything", {}, sandbox)


def test_render_refuses_container_outside_core_compose(sandbox):
    with pytest.raises(ValueError, match="not a sandbox core service"):
        render("restart_nf", {"nf": "host"}, sandbox)


def test_render_revert_config_inside_sandbox(sandbox):
    cmd = render("revert_config", {"path": "core/amf/config.yaml"}, sandbox)
    assert cmd == [f"git -C {sandbox} checkout -- core/amf/config.yaml"]


def test_render_refuses_path_escape(sandbox):
    with pytest.raises(ValueError, match="outside the sandbox"):
        render("revert_config", {"path": "../../etc/passwd"}, sandbox)


def test_render_reseed_subscriber(sandbox):
    cmd = render("reseed_subscriber", {"imsi": "999700000000001"}, sandbox)
    assert cmd == [f"docker compose --project-directory {sandbox}/core run --rm seed 999700000000001"]


def test_render_rerun_capture_known_scenario(sandbox):
    cmd = render("rerun_capture", {"scenario": "n4_upf_timeout"}, sandbox)
    assert cmd == [f"bash {sandbox}/capture.sh --scenario n4_upf_timeout"]


def test_render_refuses_unknown_scenario(sandbox):
    with pytest.raises(ValueError, match="scenario"):
        render("rerun_capture", {"scenario": "not_a_scenario"}, sandbox)


def test_render_observe_only_no_command(sandbox):
    assert render("observe_only", {}, sandbox) == []


def test_proposal_hash_is_stable_and_tamper_evident():
    p = {"action": "restart_nf", "args": {"nf": "upf"}, "justification": "j"}
    assert proposal_hash(p) == proposal_hash(dict(p))
    p2 = dict(p, args={"nf": "amf"})
    assert proposal_hash(p) != proposal_hash(p2)


def test_dry_run_never_invokes_runner(sandbox, runner):
    ex = Executor(sandbox, runner=runner)
    proposal = {"action": "restart_nf", "args": {"nf": "upf"},
                "justification": "j"}
    commands = ex.dry_run(proposal)
    assert commands == [f"docker compose --project-directory {sandbox}/core restart upf"]
    assert runner.calls == []


def test_apply_runs_checkpointed_commands(sandbox, runner):
    ex = Executor(sandbox, runner=runner)
    proposal = {"action": "restart_nf", "args": {"nf": "upf"},
                "justification": "j"}
    commands = ex.dry_run(proposal)
    ex.apply(proposal, commands)
    assert runner.calls == commands


def test_apply_refuses_commands_not_from_this_proposal(sandbox, runner):
    ex = Executor(sandbox, runner=runner)
    proposal = {"action": "restart_nf", "args": {"nf": "upf"},
                "justification": "j"}
    ex.dry_run(proposal)
    with pytest.raises(ValueError, match="checkpoint"):
        ex.apply(proposal, ["docker compose --project-directory /etc restart host"])
