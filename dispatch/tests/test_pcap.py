"""The PCAP specialist agent: `triage analyze` as a subprocess over the
decode, and Evidence items grounded in the decode inventory. An item must
match an inventory entry exactly (message name, timestamp within the
displayed-precision tolerance, claimed cause) or it is rejected — mirroring
triage's own grounded_evidence. Citations name the decode handle. The
5gcap and triage subprocesses are stubbed at their seams; Groq-free."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import dispatch.kpi as kpi_mod
from _helpers import make_kpi_runner, make_triage_runner
from dispatch.pcap import (TS_TOLERANCE, locate_evidence,
                           message_inventory, pcap_item, run_pcap_agent,
                           run_triage)

FIXTURES = Path(__file__).resolve().parents[2] / "5gcap" / "tests" / "fixtures"

# A saved triage run (committed fixture): the real n4_upf_timeout episode
# from triage/memory/episodes.jsonl in the result envelope triage prints.
SAVED_RUN = json.loads(
    (Path(__file__).parent / "fixtures" / "triage_n4_timeout.json").read_text())


EXPORT = {
    "kpis": {},
    "flows": [{
        "flow_id": 1, "procedures": [],
        "messages": [
            {"ts": 1000.0, "ngap": "InitialUEMessage",
             "nas": "5GMMRegistrationRequest", "nas_inner": None,
             "nas_cause": None},
            {"ts": 1001.5, "ngap": "DownlinkNASTransport",
             "nas": "5GMMDLNASTransport",
             "nas_inner": "PDUSessionEstablishmentReject",
             "nas_cause": {"code": 67,
                           "name": "insufficient resources for slice"}},
        ],
    }],
    "unassociated": [{"ts": 1002.0, "ngap": "HandoverRequired"}],
    "n4": {"messages": [
        {"ts": 1003.0, "name": "PFCP Session Establishment Request",
         "cause_code": None, "flow_id": None},
        {"ts": 1004.0, "name": "PFCP Session Establishment Response",
         "cause_code": 190, "flow_id": None},
    ]},
    "sbi": {"messages": [
        {"ts": 1005.0, "name": "SmContextCreate", "status": 404,
         "flow_id": 1},
    ]},
}


# --- the decode inventory ---

def test_inventory_indexes_every_decodable_message_by_handle():
    inv = message_inventory(EXPORT)
    by_name = {(e["handle"], e["name"]): e for e in inv}
    # Handles are 1-based: triage's evidence listings enumerate from [1]
    # and resolve msgs[idx - 1], so the citation must agree.
    assert by_name[("flow:1:1", "5GMMRegistrationRequest")]["cause"] is None
    assert by_name[("flow:1:1", "InitialUEMessage")]["plane"] == "n2"
    assert by_name[("flow:1:2", "PDUSessionEstablishmentReject")]["cause"] == 67
    assert by_name[("flow:1:2", "5GMMDLNASTransport")]["flow_id"] == 1
    # Unassociated, N4, SBI.
    assert by_name[("unassociated:1", "HandoverRequired")]["cause"] is None
    assert by_name[("n4:1", "PFCP Session Establishment Request")]["cause"] \
        is None
    assert by_name[("n4:2", "PFCP Session Establishment Response")]["cause"] \
        == 190
    assert by_name[("sbi:1", "SmContextCreate")]["flow_id"] == 1
    assert by_name[("sbi:1", "SmContextCreate")]["cause"] is None


def test_inventory_skips_nameless_or_timestampless_messages():
    export = {"flows": [{"flow_id": 1, "messages": [
        {"ts": 1000.0, "nas": None, "nas_inner": None, "ngap": None},
        {"ts": None, "nas": "5GMMRegistrationAccept"},
    ]}], "unassociated": [], "n4": {"messages": [
        {"ts": 1001.0, "name": None},
    ]}, "sbi": {"messages": []}}
    assert message_inventory(export) == []


# --- the grounding check (triage's grounded_evidence semantics) ---

def test_locate_matches_name_ts_within_tolerance_and_claimed_cause():
    inv = message_inventory(EXPORT)
    match = locate_evidence(inv, {"message": "PDUSessionEstablishmentReject",
                                  "ts": 1001.5003, "cause": 67})
    assert match is not None and match["handle"] == "flow:1:2"


def test_locate_rejects_ts_outside_tolerance():
    inv = message_inventory(EXPORT)
    # 1001.5003 (within tolerance) passes; 1001.51 is outside.
    assert locate_evidence(inv, {"message": "PDUSessionEstablishmentReject",
                                 "ts": 1001.5003}) is not None
    assert locate_evidence(inv, {"message": "PDUSessionEstablishmentReject",
                                 "ts": 1001.51}) is None
    assert TS_TOLERANCE == 5e-4


def test_locate_rejects_claimed_cause_mismatch():
    inv = message_inventory(EXPORT)
    assert locate_evidence(inv, {"message": "PDUSessionEstablishmentReject",
                                 "ts": 1001.5, "cause": 7}) is None


def test_locate_allows_unclaimed_cause():
    # A null cause is "not claimed", never a mismatch (triage semantics —
    # the n4_upf_timeout episodes cite requests with cause null).
    inv = message_inventory(EXPORT)
    match = locate_evidence(inv, {"message": "PDUSessionEstablishmentReject",
                                  "ts": 1001.5, "cause": None})
    assert match is not None and match["cause"] == 67


def test_locate_rejects_unknown_message_or_timestampless_claim():
    inv = message_inventory(EXPORT)
    assert locate_evidence(inv, {"message": "FabricatedReject",
                                 "ts": 1001.5}) is None
    assert locate_evidence(inv, {"message": "PDUSessionEstablishmentReject",
                                 "cause": 67}) is None
    assert locate_evidence(inv, "not a claim") is None


# --- the evidence item ---

def test_pcap_item_is_grounded_and_cited_by_handle():
    inv = message_inventory(EXPORT)
    match = locate_evidence(inv, {"message": "PDUSessionEstablishmentReject",
                                  "ts": 1001.5, "cause": 67})
    item = pcap_item(match, "explicit reject")
    assert item["source"] == "pcap"
    assert item["kind"] == "explicit reject"
    assert item["ts"] == 1001.5
    assert item["entry"] == "PDUSessionEstablishmentReject cause 67"
    assert item["cause"] == "67"
    assert item["keys"] == {"flow_id": 1}
    assert item["citation"] == "flow:1:2"


def test_pcap_item_without_cause_or_flow_id():
    inv = message_inventory(EXPORT)
    match = locate_evidence(inv, {"message": "PFCP Session Establishment "
                                 "Request", "ts": 1003.0, "cause": None})
    item = pcap_item(match, "no terminal message (timeout)")
    assert item["entry"] == "PFCP Session Establishment Request"
    assert item["cause"] is None
    assert item["keys"] == {}
    assert item["citation"] == "n4:1"


# --- the triage subprocess seam ---

def test_run_triage_builds_command_and_parses_stdout(tmp_path):
    export = tmp_path / "export.json"
    export.write_text("{}")
    calls = []
    results = run_triage(export, make_triage_runner([{"plane": "n4"}], calls))
    assert results == [{"plane": "n4"}]
    assert "triage analyze" in calls[0]
    assert str(export) in calls[0]


def test_run_triage_nonzero_exit_raises():
    with pytest.raises(ValueError, match="triage analyze failed"):
        run_triage(Path("x.json"), lambda cmd, **kw: 1)


def test_run_triage_non_json_stdout_raises():
    bad = SimpleNamespace(returncode=0, stdout="not json", stderr="")
    with pytest.raises(ValueError, match="not JSON"):
        run_triage(Path("x.json"), lambda cmd, **kw: bad)


# --- the PCAP agent ---

def _results():
    """One result whose episode cites a grounded claim plus two that must be
    rejected: an absent message name and a wrong cause."""
    return [{"plane": "n4", "flow_id": None, "procedure": "session_"
             "establishment", "shape": "no terminal message (timeout)",
             "detail": None, "episode": {
                 "incident_type": "n4_upf_timeout",
                 "narrative": "no Session Establishment Response arrived.",
                 "cited_evidence": [
                     {"message": "PFCP Session Establishment Request",
                      "cause": None, "ts": 1003.0},
                     {"message": "FabricatedRequest", "cause": None,
                      "ts": 1003.0},
                     {"message": "PFCP Session Establishment Response",
                      "cause": 3, "ts": 1004.0},
                 ]}}]


def test_run_pcap_agent_without_n2_capture_never_runs(monkeypatch):
    calls = []
    monkeypatch.setattr(kpi_mod.subprocess, "run",
                        lambda cmd, **kw: calls.append(cmd))
    assert run_pcap_agent({"n4": "n4.pcap"}) == []
    assert calls == []


def test_run_pcap_agent_grounds_and_rejects(monkeypatch):
    monkeypatch.setattr(kpi_mod.subprocess, "run", make_kpi_runner(EXPORT))
    items = run_pcap_agent({"n2": "n2.pcap"},
                           triage_runner=make_triage_runner(_results()))
    # The hallucinated message and the wrong cause are rejected, never
    # recorded; only the exact match survives, cited by its handle.
    assert len(items) == 1
    assert items[0]["citation"] == "n4:1"
    assert items[0]["kind"] == "no terminal message (timeout)"
    assert items[0]["ts"] == 1003.0


def test_run_pcap_agent_5gcap_failure_is_graceful(monkeypatch):
    monkeypatch.setattr(kpi_mod.subprocess, "run", lambda cmd, **kw: 1)
    assert run_pcap_agent({"n2": "n2.pcap"}) == []


def test_run_pcap_agent_triage_failure_is_graceful(monkeypatch):
    monkeypatch.setattr(kpi_mod.subprocess, "run", make_kpi_runner(EXPORT))
    assert run_pcap_agent({"n2": "n2.pcap"},
                          triage_runner=lambda cmd, **kw: 1) == []


def test_run_pcap_agent_malformed_result_is_graceful(monkeypatch):
    monkeypatch.setattr(kpi_mod.subprocess, "run", make_kpi_runner(EXPORT))
    results = ["not a result", {"episode": None},
               {"shape": None, "plane": "n4", "procedure": None,
                "episode": {"cited_evidence": [{"message": 3, "ts": 1003.0}]}}]
    assert run_pcap_agent({"n2": "n2.pcap"},
                          triage_runner=make_triage_runner(results)) == []


# --- the real decode: AC-1, unstubbed 5gcap on the committed scenario
# captures, the saved run's cited claim grounded against the real
# inventory (test_baseline.py already pays for real 5gcap in this suite) ---

def test_real_n4_upf_timeout_captures_emit_grounded_items():
    items = run_pcap_agent({
        "n2": FIXTURES / "n4_upf_timeout.pcap",
        "n4": FIXTURES / "n4_upf_timeout_n4.pcap",
        "sbi": FIXTURES / "n4_upf_timeout_sbi.pcap",
    }, triage_runner=make_triage_runner(SAVED_RUN))
    assert len(items) == 1
    item = items[0]
    assert item["source"] == "pcap"
    assert item["kind"] == "no terminal message (timeout)"
    assert item["entry"] == "PFCP Session Establishment Request"
    assert item["ts"] == 1788516709.569422  # the inventory's exact ts
    assert item["citation"] == "n4:9"       # the 1-based decode handle
