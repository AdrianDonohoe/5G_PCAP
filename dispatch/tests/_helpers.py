"""Shared helpers for the dispatch suite. Not a test module — pytest's
collection patterns (test_*.py, *_test.py) skip it."""

import json
import re
from pathlib import Path
from types import SimpleNamespace

import dispatch.kpi as kpi_mod
import dispatch.log as log_mod
import dispatch.pcap as pcap_mod
import dispatch.root_cause as root_cause_mod


def make_kpi_runner(export, calls=None, returncode=0):
    """A runner fake for the 5gcap subprocess seam: writes the canned export
    to the --json path named in the command and returns the exit code."""
    def fake(cmd, **kw):
        if calls is not None:
            calls.append(cmd)
        m = re.search(r"--json (\S+)", cmd)
        assert m, "run_analyze must pass --json <path>"
        with open(m.group(1), "w") as f:
            json.dump(export, f)
        return returncode

    return fake


def make_triage_runner(results, calls=None, returncode=0):
    """A runner fake for the triage analyze seam: asserts the export path
    named in the command exists (the caller wrote it), and returns the
    canned results array on stdout."""
    def fake(cmd, **kw):
        if calls is not None:
            calls.append(cmd)
        m = re.search(r"triage analyze (\S+)", cmd)
        assert m, "run_triage must pass the export path"
        assert Path(m.group(1)).exists(), "run_triage must write the export"
        return SimpleNamespace(returncode=returncode,
                               stdout=json.dumps(results), stderr="")

    return fake


def make_log_runner(windowed_text, calls=None, returncode=0):
    """A runner fake for the docker compose logs seam: returns the canned
    windowed output on stdout."""
    def fake(cmd, **kw):
        if calls is not None:
            calls.append(cmd)
        return SimpleNamespace(returncode=returncode, stdout=windowed_text,
                               stderr="")

    return fake


def stub_specialist_seams(monkeypatch):
    """Blanket failing stubs for the specialist seams: the 5gcap, triage
    and docker compose subprocess seams, plus the log extraction's and
    the root-cause search's live defaults. Graph and CLI tests that don't
    exercise a specialist explicitly must never spawn a real subprocess
    or build a Groq-backed predictor (ADR-0002); a failing seam degrades
    the nodes to no evidence, which is their real failure behavior."""
    def failing(cmd, **kw):
        return SimpleNamespace(returncode=1,
                               stderr="specialist subprocess stubbed",
                               stdout="")

    monkeypatch.setattr(kpi_mod.subprocess, "run", failing)
    monkeypatch.setattr(pcap_mod.subprocess, "run", failing)
    monkeypatch.setattr(log_mod.subprocess, "run", failing)

    def no_live_extractor():
        raise RuntimeError("live log extraction stubbed (ADR-0002)")

    monkeypatch.setattr(log_mod, "default_extract", no_live_extractor)

    def no_live_search(evidence, links):
        raise RuntimeError("live root-cause search stubbed (ADR-0002)")

    monkeypatch.setattr(root_cause_mod, "default_search", no_live_search)
