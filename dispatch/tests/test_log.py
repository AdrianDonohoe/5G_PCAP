"""The Log specialist agent: docker stdout logs for the event's time
window, LLM extraction proposes Evidence items, and a code-enforced
grounding check keeps only items whose citation is an exact line of the
windowed pull — a cited line outside the window is rejected. Citations
are exact log lines; the item's ts comes from the cited line's docker
timestamp prefix, not the proposal. The docker compose subprocess and the
extraction are stubbed at their seams; Groq-free (ADR-0002)."""

import json
from pathlib import Path

import pytest

from _helpers import make_log_runner
from dispatch.log import ground_log_item, run_docker_logs, run_log_agent

FIXTURES = Path(__file__).parent / "fixtures"
EVENT = json.loads((FIXTURES / "event_n4_timeout.json").read_text())
WINDOWED = (FIXTURES / "core_logs_n4_timeout.txt").read_text()
WINDOWED_LINES = {line.rstrip("\r\n") for line in WINDOWED.splitlines()}

# The synthetic fixture's in-window lines carry docker compose's
# `--timestamps` prefix; the event window is 15:05:00Z-15:08:20Z.
UPF_LINE = ("upf     | 2025-06-15T15:05:01.510724553Z [open5gs-upf] INFO "
            "[upf] PFCP[0] Session Establishment Request "
            "(../src/upf/pfcp-sm.c:225)")
# A real sandbox line, but 15:30:00Z falls outside the event window, so
# the windowed pull never contains it.
LATE_LINE = ("upf     | 2025-06-15T15:30:00.000000000Z [open5gs-upf] INFO "
             "[upf] PFCP[0] Session Establishment Request "
             "(../src/upf/pfcp-sm.c:225)")


def _proposal(citation=UPF_LINE, **overrides):
    proposal = {"kind": "request unanswered",
                "entry": "UPF logs the request but never answers",
                "keys": {"nf": "upf"}, "citation": citation}
    proposal.update(overrides)
    return proposal


# --- the docker compose logs seam ---

def test_run_docker_logs_builds_windowed_command(tmp_path):
    calls = []
    text = run_docker_logs(tmp_path,
                           {"start": 1749999900.0, "end": 1750000100.0},
                           make_log_runner("line", calls))
    assert text == "line"
    assert calls == [f"docker compose --project-directory {tmp_path}/core "
                     f"logs --timestamps --since 2025-06-15T15:05:00+00:00 "
                     f"--until 2025-06-15T15:08:20+00:00"]


def test_run_docker_logs_nonzero_exit_raises(tmp_path):
    with pytest.raises(ValueError, match="docker compose logs failed"):
        run_docker_logs(tmp_path, {"start": 0.0, "end": 1.0},
                        lambda cmd, **kw: 1)


# --- the grounding check ---

def test_ground_log_item_accepts_exact_line():
    item = ground_log_item(_proposal(), WINDOWED_LINES,
                           EVENT["time_window"])
    assert item is not None
    assert item["source"] == "log"          # set in code, never proposed
    assert item["kind"] == "request unanswered"
    assert item["entry"] == "UPF logs the request but never answers"
    assert item["keys"] == {"nf": "upf"}
    assert item["citation"] == UPF_LINE     # the exact log line
    # The ts is read off the cited line's docker prefix, not the proposal.
    assert item["ts"] == 1749999901.510724
    assert 1749999900.0 < item["ts"] < 1750000100.0


def test_ground_log_item_rejects_line_outside_window():
    assert ground_log_item(_proposal(citation=LATE_LINE), WINDOWED_LINES,
                           EVENT["time_window"]) is None


def test_ground_log_item_rejects_window_line_with_out_of_window_ts():
    # The line IS in the pull (docker flags misfired), but its timestamp
    # falls outside the event window: the bounds check, not membership,
    # rejects it — the window is enforced in code.
    lines = {LATE_LINE} | WINDOWED_LINES
    assert ground_log_item(_proposal(citation=LATE_LINE), lines,
                           EVENT["time_window"]) is None


def test_ground_log_item_rejects_fabricated_or_malformed_citations():
    for bad in ("the upf exploded", "", None, 3, UPF_LINE + "x"):
        assert ground_log_item(_proposal(citation=bad), WINDOWED_LINES,
                               EVENT["time_window"]) is None
    assert ground_log_item("not a proposal", WINDOWED_LINES,
                           EVENT["time_window"]) is None


def test_ground_log_item_rejects_missing_kind_or_entry():
    assert ground_log_item(_proposal(kind=""), WINDOWED_LINES,
                           EVENT["time_window"]) is None
    assert ground_log_item(_proposal(entry=""), WINDOWED_LINES,
                           EVENT["time_window"]) is None
    no_kind = _proposal()
    del no_kind["kind"]
    assert ground_log_item(no_kind, WINDOWED_LINES,
                           EVENT["time_window"]) is None


def test_ground_log_item_rejects_line_without_timestamp_prefix():
    lines = {"no docker timestamp here"} | WINDOWED_LINES
    assert ground_log_item(_proposal(citation="no docker timestamp here"),
                           lines, EVENT["time_window"]) is None


def test_ground_log_item_defaults_missing_keys():
    item = ground_log_item(_proposal(keys=None), WINDOWED_LINES,
                           EVENT["time_window"])
    assert item is not None and item["keys"] == {}


# --- the log agent ---

def test_run_log_agent_grounds_and_rejects(tmp_path):
    calls = []

    def extract(text, event):
        assert text == WINDOWED
        return [
            _proposal(),                              # grounded
            _proposal(citation=LATE_LINE),            # outside the window
            _proposal(citation="the upf exploded"),   # fabricated
            "not an item",                            # malformed
        ]

    items = run_log_agent(EVENT, tmp_path,
                          log_runner=make_log_runner(WINDOWED, calls),
                          extractor=extract)
    # Only the exact in-window line survives; the rest are rejected,
    # never recorded.
    assert len(items) == 1
    assert items[0]["citation"] == UPF_LINE
    assert items[0]["source"] == "log"
    assert len(calls) == 1


def test_run_log_agent_docker_failure_is_graceful(tmp_path):
    items = run_log_agent(EVENT, tmp_path,
                          log_runner=lambda cmd, **kw: 1,
                          extractor=lambda text, event: [])
    assert items == []


def test_run_log_agent_extraction_failure_is_graceful(tmp_path):
    def boom(text, event):
        raise RuntimeError("GROQ_API_KEY is not set")

    items = run_log_agent(EVENT, tmp_path, log_runner=make_log_runner(WINDOWED),
                          extractor=boom)
    assert items == []


def test_run_log_agent_non_list_extraction_is_graceful(tmp_path):
    items = run_log_agent(EVENT, tmp_path, log_runner=make_log_runner(WINDOWED),
                          extractor=lambda text, event: "nope")
    assert items == []
