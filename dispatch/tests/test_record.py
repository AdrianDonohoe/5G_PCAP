"""The Incident Record is deterministic Markdown with six sections."""

from dispatch.record import render_record


def _sample(**overrides):
    rec = {
        "event": {"incident_id": "inc-1", "detected_at": 1750000000.0,
                  "source": "human", "procedure": "n4_upf_timeout",
                  "time_window": {"start": 1749999900.0, "end": 1750000100.0},
                  "description": "desc"},
        "evidence": [{"source": "pcap", "kind": "k", "ts": 1750000000.0,
                      "entry": "e", "cause": None, "endpoints": None,
                      "keys": {"nf": "upf"}, "citation": "c"}],
        "links": [],
        "root_cause": "The UPF is stuck.",
        "proposal": {"action": "restart_nf", "args": {"nf": "upf"},
                     "justification": "j", "commands": ["docker compose restart upf"],
                     "hash": "h"},
        "approval": "pending",
        "execution_log": [],
    }
    rec.update(overrides)
    return rec


def test_all_six_sections_present():
    md = render_record(_sample())
    for section in ("Event", "Correlation graph", "Root cause", "Proposal",
                    "Approval status", "Execution log"):
        assert f"## {section}" in md


def test_rendering_is_deterministic():
    assert render_record(_sample()) == render_record(_sample())


def test_evidence_citations_render():
    md = render_record(_sample())
    assert "cited: c" in md


def test_root_cause_falls_back_when_empty():
    md = render_record(_sample(root_cause=""))
    assert "- (no root cause produced)" in md


def test_approval_status_variants():
    assert "Approval status: **pending**" in render_record(_sample(approval="pending"))
    assert "**approved (dry-run)**" in render_record(_sample(approval="approved-dry-run"))
    assert "**approved (executed)**" in render_record(_sample(approval="approved-executed"))
    assert "**rejected**" in render_record(_sample(approval="rejected"))


def test_execution_log_lines_rendered():
    rec = _sample(approval="approved-executed",
                  execution_log=["dry-run: docker compose restart upf",
                                 "executed: docker compose restart upf"])
    md = render_record(rec)
    assert "dry-run: docker compose restart upf" in md
    assert "executed: docker compose restart upf" in md
