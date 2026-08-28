"""Shared fixtures for the dispatch suite."""

import pytest

from _helpers import stub_specialist_seams

# Modules that own the real subprocess seam: their real-capture tests run
# unstubbed 5gcap on the committed fixtures (the ADR-sanctioned exception,
# like 5gcap's test_baseline.py), and the baseline regeneration test runs
# its own script. Everywhere else the specialist nodes must never spawn a
# real 5gcap, triage or docker process, nor build a Groq-backed predictor
# (ADR-0002); a failing seam degrades each node to no evidence, which is
# their real behavior.
_REAL_SEAM_MODULES = ("test_kpi", "test_pcap", "test_baseline")


@pytest.fixture(autouse=True)
def _stub_specialist_seams(monkeypatch, request):
    if request.module.__name__ in _REAL_SEAM_MODULES:
        return
    stub_specialist_seams(monkeypatch)
