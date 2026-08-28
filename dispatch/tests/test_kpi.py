"""The KPI comparator: pure, exhaustive, offline. Three degradation rules —
success rate below golden, latency above twice golden, any cause-bearing
reject message — over the computed kpis and the export's message sections.
The 5gcap subprocess is stubbed at the runner seam."""

import json
from pathlib import Path

import pytest

from _helpers import make_kpi_runner
from dispatch.kpi import (GOLDEN_PATH, LATENCY_KEYS, alarm_event,
                          capture_window, detect_kpi, deviations,
                          kpi_evidence, load_golden, passes_grounding,
                          run_analyze, run_kpi_agent)

# The committed Golden baseline is the comparator's contract — tests read
# it directly so they track baseline regeneration, never a hand copy.
GOLDEN = load_golden()

FIXTURES = Path(__file__).resolve().parents[2] / "5gcap" / "tests" / "fixtures"


def _flow(flow_id=1, nas_cause=None, ts=1750000000.0,
          nas="5GMMRegistrationReject", nas_inner=None):
    message = {"ts": ts, "nas": nas, "nas_inner": nas_inner,
               "nas_cause": nas_cause, "kind": "downlink", "unparsed": None}
    return {"flow_id": flow_id, "messages": [message], "procedures": []}


def _healthy_sections():
    return {
        "flows": [_flow(nas_cause=None, nas="5GMMRegistrationAccept")],
        "n4": {"messages": [{"ts": 1750000001.0, "name": "PFCP Session "
                             "Establishment Response", "cause": "Request "
                             "accepted", "cause_code": 1, "flow_id": 1}]},
        "sbi": {"messages": [{"ts": 1750000002.0, "name": "SmContextCreate",
                              "status": 201, "problem_title": None,
                              "flow_id": 1}]},
    }


def _export(kpis, sections=None):
    return {"kpis": kpis, **(sections or _healthy_sections())}


# --- the three rules, pure ---

def test_healthy_is_empty():
    assert deviations(GOLDEN, GOLDEN, **_healthy_sections()) == []


def test_success_rate_below_golden():
    kpis = dict(GOLDEN, procedure_success_rate=0.8,
                procedure_successes=4, procedure_failures=1)
    devs = deviations(kpis, GOLDEN, **_healthy_sections())
    assert [d["rule"] for d in devs] == ["success_rate"]
    assert devs[0]["kpi"] == "procedure_success_rate"
    assert "0.8" in devs[0]["detail"] and "1.0" in devs[0]["detail"]


def test_success_rate_equal_or_above_golden_is_healthy():
    for rate in (1.0, 1.1):
        kpis = dict(GOLDEN, procedure_success_rate=rate)
        assert deviations(kpis, GOLDEN, **_healthy_sections()) == []


def test_latency_above_twice_golden():
    kpis = dict(GOLDEN, attach_time_ms=300.0)
    devs = deviations(kpis, GOLDEN, **_healthy_sections())
    assert [d["rule"] for d in devs] == ["latency"]
    assert devs[0]["kpi"] == "attach_time_ms"


def test_latency_exactly_twice_golden_is_healthy():
    kpis = dict(GOLDEN, attach_time_ms=2 * GOLDEN["attach_time_ms"])
    assert deviations(kpis, GOLDEN, **_healthy_sections()) == []


def test_latency_below_twice_golden_is_healthy():
    kpis = dict(GOLDEN, attach_time_ms=1.9 * GOLDEN["attach_time_ms"])
    assert deviations(kpis, GOLDEN, **_healthy_sections()) == []


def test_latency_rule_covers_every_latency_kpi():
    # Every latency key the export can carry must be under the rule.
    for name in LATENCY_KEYS:
        kpis = dict(GOLDEN, **{name: 2 * GOLDEN[name] + 1})
        devs = deviations(kpis, GOLDEN, **_healthy_sections())
        assert [d["rule"] for d in devs] == ["latency"]
        assert devs[0]["kpi"] == name


def test_latency_keys_missing_from_computed_are_ignored():
    kpis = dict(GOLDEN)
    del kpis["sbi_to_n4_ms"]  # N2-only runs lack the cross-plane keys
    assert deviations(kpis, GOLDEN, **_healthy_sections()) == []


REJECT_CAUSE = {"code": 7, "name": "5GS services not allowed"}


def test_nas_reject_message_is_cause_bearing():
    sections = _healthy_sections()
    sections["flows"].append(_flow(flow_id=2, nas_cause=REJECT_CAUSE,
                                   ts=1750000005.0))
    devs = deviations(GOLDEN, GOLDEN, **sections)
    causes = [d for d in devs if d["rule"] == "cause"]
    assert len(causes) == 1
    assert causes[0]["flow_id"] == 2
    assert causes[0]["ts"] == 1750000005.0
    assert "nas_cause 7" in causes[0]["detail"]
    assert "5GS services not allowed" in causes[0]["detail"]
    # The ticket's alarm names the deviating KPI for every rule.
    assert causes[0]["kpi"] == "procedure_failures"
    assert "kpi.procedure_failures" in causes[0]["detail"]


def test_5gsm_reject_inside_nas_transport_fires_on_inner_name():
    # 5GSM rejects arrive inside DL NAS transports; the reject name is the
    # inner message, and that is what the rule and the detail must use.
    sections = _healthy_sections()
    sections["flows"].append(_flow(
        flow_id=3, nas="5GMMDLNASTransport",
        nas_inner="PDUSessionEstablishmentReject",
        nas_cause={"code": 67,
                   "name": "insufficient resources for slice"},
        ts=1750000005.0))
    devs = deviations(GOLDEN, GOLDEN, **sections)
    causes = [d for d in devs if d["rule"] == "cause"]
    assert len(causes) == 1
    assert "PDUSessionEstablishmentReject nas_cause 67" in causes[0]["detail"]


def test_cause_on_non_reject_message_never_fires():
    # Cause IEs also ride on non-rejects (AuthenticationFailure, 5GMMStatus,
    # seen in real captures) — the ticket's rule is reject messages only.
    sections = _healthy_sections()
    sections["flows"].append(_flow(
        flow_id=2, nas="5GMMAuthenticationFailure",
        nas_cause={"code": 22, "name": "Congestion"}, ts=1750000005.0))
    assert deviations(GOLDEN, GOLDEN, **sections) == []


def test_n4_non_accepted_cause_code_is_cause_bearing():
    sections = _healthy_sections()
    sections["n4"]["messages"].append(
        {"ts": 1750000006.0, "name": "PFCP Session Establishment Response",
         "cause": "No resources available", "cause_code": 190, "flow_id": 1})
    devs = deviations(GOLDEN, GOLDEN, **sections)
    causes = [d for d in devs if d["rule"] == "cause"]
    assert len(causes) == 1
    assert "190" in causes[0]["detail"]


def test_n4_accepted_causes_never_fire():
    # The golden triple is full of "Request accepted" / cause_code 1.
    sections = _healthy_sections()
    sections["n4"]["messages"] += [
        {"ts": 1750000007.0, "name": "PFCP Heartbeat Response",
         "cause": "Request accepted", "cause_code": 1, "flow_id": None},
        {"ts": 1750000008.0, "name": "PFCP Heartbeat Request",
         "cause": None, "cause_code": None, "flow_id": None},
    ]
    assert deviations(GOLDEN, GOLDEN, **sections) == []


def test_sbi_error_status_is_cause_bearing():
    sections = _healthy_sections()
    sections["sbi"]["messages"].append(
        {"ts": 1750000009.0, "name": "SmContextCreate", "status": 404,
         "problem_title": "CONTEXT_NOT_FOUND", "flow_id": None})
    devs = deviations(GOLDEN, GOLDEN, **sections)
    causes = [d for d in devs if d["rule"] == "cause"]
    assert len(causes) == 1
    assert "404" in causes[0]["detail"]


def test_missing_sections_never_fire():
    assert deviations(GOLDEN, GOLDEN, flows=[]) == []


# --- the alarm event ---

def test_alarm_event_none_when_healthy():
    assert alarm_event([], GOLDEN, {}, "inc-x", 1.0, (0.0, 1.0)) is None


def test_alarm_event_shapes_and_names_deviating_kpis():
    devs = [{"rule": "success_rate", "kpi": "procedure_success_rate",
             "detail": "procedure_success_rate 0.8 below golden 1.0"}]
    event = alarm_event(devs, GOLDEN, {"n2": "x.pcap"}, "inc-kpi-1",
                        1750000000.0, (1749999900.0, 1750000000.0))
    assert event["incident_id"] == "inc-kpi-1"
    assert event["source"] == "kpi"
    assert event["detected_at"] == 1750000000.0
    assert event["time_window"] == {"start": 1749999900.0,
                                    "end": 1750000000.0}
    assert "procedure_success_rate" in event["description"]
    assert event["kpi"] == GOLDEN
    assert event["captures"] == {"n2": "x.pcap"}


# --- evidence + grounding ---

def test_kpi_evidence_items_are_grounded():
    kpis = dict(GOLDEN, procedure_success_rate=0.8,
                procedure_successes=4, procedure_failures=1)
    devs = [{"rule": "success_rate", "kpi": "procedure_success_rate",
             "detail": "procedure_success_rate 0.8 below golden 1.0"},
            {"rule": "cause", "kpi": "procedure_failures",
             "detail": "reject message: 5GMMRegistrationReject nas_cause 7",
             "cause": "7", "flow_id": 2, "ts": 1750000005.0}]
    items = kpi_evidence(devs, kpis, detected_at=1750000010.0)
    assert len(items) == 2
    for item in items:
        assert item["source"] == "kpi"
        assert passes_grounding(item, kpis)
    assert items[0]["citation"] == "kpi.procedure_success_rate=0.8"
    cause_item = [i for i in items if i["cause"] == "7"][0]
    assert cause_item["kind"] == "reject message"
    assert cause_item["citation"] == "kpi.procedure_failures=1"
    assert cause_item["keys"] == {"flow_id": 2}
    assert cause_item["ts"] == 1750000005.0


def test_grounding_rejects_unknown_or_mismatched_citations():
    kpis = {"procedure_failures": 1}
    good = {"citation": "kpi.procedure_failures=1"}
    assert passes_grounding(good, kpis)
    assert not passes_grounding({"citation": "kpi.nope=1"}, kpis)
    assert not passes_grounding({"citation": "kpi.procedure_failures=2"}, kpis)
    assert not passes_grounding({"citation": "not a citation"}, kpis)


# --- the 5gcap subprocess seam ---

def test_run_analyze_builds_command_and_parses_export():
    calls = []
    result = run_analyze({"n2": "n2.pcap", "sbi": "sbi.pcap",
                          "n4": "n4.pcap"},
                         runner=make_kpi_runner(_export(GOLDEN), calls))
    assert result["kpis"] == GOLDEN
    cmd = calls[0]
    assert "5gcap analyze" in cmd
    assert "n2.pcap" in cmd and "--sbi sbi.pcap" in cmd and "--n4 n4.pcap" in cmd


def test_run_analyze_n2_only_omits_plane_flags():
    calls = []
    run_analyze({"n2": "n2.pcap"},
                runner=make_kpi_runner(_export(GOLDEN), calls))
    assert "--sbi" not in calls[0] and "--n4" not in calls[0]


def test_run_analyze_requires_n2_capture():
    with pytest.raises(ValueError, match="N2 capture"):
        run_analyze({"n4": "n4.pcap"}, runner=lambda cmd, **kw: 0)


def test_run_analyze_nonzero_exit_raises():
    with pytest.raises(ValueError, match="5gcap analyze failed"):
        run_analyze({"n2": "n2.pcap"}, runner=lambda cmd, **kw: 1)


def test_run_analyze_export_without_kpis_raises():
    # An N4-only capture analyzes fine but carries no N2 KPIs — the
    # comparator must refuse it cleanly, not KeyError mid-run.
    with pytest.raises(ValueError, match="no kpis"):
        run_analyze({"n2": "n4-disguised.pcap"},
                    runner=make_kpi_runner({"messages": []}))


def test_load_golden_reads_committed_baseline(tmp_path, monkeypatch):
    golden = tmp_path / "golden.json"
    golden.write_text(json.dumps({"procedure_success_rate": 1.0}))
    monkeypatch.setattr("dispatch.kpi.GOLDEN_PATH", golden)
    assert load_golden() == {"procedure_success_rate": 1.0}
    assert GOLDEN_PATH.is_absolute()  # the committed default resolves


# --- the KPI agent ---

def test_run_kpi_agent_without_n2_capture_never_runs():
    calls = []

    def fake(cmd, **kw):
        calls.append(cmd)
        return 0

    assert run_kpi_agent({"n4": "n4.pcap"}, runner=fake) == []
    assert calls == []


def test_run_kpi_agent_analyze_failure_is_graceful():
    assert run_kpi_agent({"n2": "n2.pcap"},
                         runner=lambda cmd, **kw: 1) == []


def test_run_kpi_agent_healthy_emits_nothing():
    assert run_kpi_agent({"n2": "n2.pcap"},
                         runner=make_kpi_runner(_export(GOLDEN))) == []


def test_run_kpi_agent_degraded_emits_grounded_items():
    kpis = dict(GOLDEN, procedure_success_rate=0.8,
                procedure_successes=4, procedure_failures=1)
    sections = _healthy_sections()
    sections["flows"].append(_flow(flow_id=2, nas_cause=REJECT_CAUSE,
                                   ts=1750000005.0))
    items = run_kpi_agent({"n2": "n2.pcap"},
                          runner=make_kpi_runner(_export(kpis, sections)))
    assert len(items) == 2
    assert all(passes_grounding(item, kpis) for item in items)


def test_run_kpi_agent_export_without_kpis_is_graceful():
    assert run_kpi_agent({"n2": "n4-disguised.pcap"},
                         runner=make_kpi_runner({"messages": []})) == []


def test_run_kpi_agent_timestampless_degraded_export_is_graceful():
    # A degraded export with no message timestamps cannot frame a window;
    # the node yields nothing rather than aborting incident handling.
    kpis = dict(GOLDEN, procedure_success_rate=0.8,
                procedure_successes=4, procedure_failures=1)
    assert run_kpi_agent(
        {"n2": "n2.pcap"},
        runner=make_kpi_runner({"kpis": kpis, "flows": [], "n4": {},
                                "sbi": {}})) == []


def test_detect_kpi_returns_event_only_when_degraded():
    assert detect_kpi({"n2": "n2.pcap"},
                      runner=make_kpi_runner(_export(GOLDEN))) is None
    kpis = dict(GOLDEN, procedure_success_rate=0.8,
                procedure_successes=4, procedure_failures=1)
    event = detect_kpi({"n2": "n2.pcap"},
                       runner=make_kpi_runner(_export(kpis)))
    assert event["source"] == "kpi"
    assert event["detected_at"] == 1750000002.0  # max message ts
    assert capture_window(_export(GOLDEN)) == (1750000000.0, 1750000002.0)


def test_detect_kpi_export_without_kpis_raises():
    with pytest.raises(ValueError, match="no kpis"):
        detect_kpi({"n2": "n4-disguised.pcap"},
                   runner=make_kpi_runner({"messages": []}))


# --- real 5gcap runs: the subprocess seam, unstubbed, on the committed
# fixtures (test_baseline.py already pays for real 5gcap in this suite) ---

def test_real_golden_triple_emits_nothing():
    event = detect_kpi({
        "n2": FIXTURES / "sandbox_n2.pcap",
        "sbi": FIXTURES / "sandbox_sbi.pcap",
        "n4": FIXTURES / "sandbox_n4.pcap",
    })
    assert event is None


def test_real_reject_capture_emits_event():
    event = detect_kpi({"n2": FIXTURES / "registration_reject.pcap"})
    assert event is not None
    assert event["source"] == "kpi"
    assert "procedure_success_rate" in event["description"]
    assert "5GMMRegistrationReject nas_cause 7" in event["description"]
    assert "kpi.procedure_failures" in event["description"]
