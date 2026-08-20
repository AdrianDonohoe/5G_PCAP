"""inspect_decoded_evidence tests against the golden 5gcap exports plus
synthetic mini-captures for the failure shapes the golden capture lacks
(cause-bearing rejects, protected inner messages, partial flows).

The golden fixtures are real 5gcap --json output; regenerate with (from
5gcap/): `uv run 5gcap analyze tests/fixtures/sandbox_n2.pcap --json
../triage/tests/fixtures/golden_n2.json` (and the N4 analog).
"""

import json
from pathlib import Path

import pytest

from triage.evidence import (DecodedCapture, inspect_decoded_evidence,
                             load_capture)

FIXTURES = Path(__file__).parent / "fixtures"


def golden():
    return load_capture(FIXTURES / "golden_n2.json",
                        FIXTURES / "golden_n4.json")


def mini_capture():
    """A synthetic N2/N4 capture carrying the failure shapes the golden
    capture doesn't: a protected inner 5GMMStatus and a cause-bearing
    RegistrationRequest, plus a partial flow."""
    return DecodedCapture(n2={
        "kpis": {"procedure_failures": 1, "procedure_success_rate": 0.5},
        "flows": [{
            "flow_id": 1, "ran_ue_ngap_id": 7, "amf_ue_ngap_id": 8,
            "partial": True,
            "messages": [
                {"ts": 1000.0, "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1",
                 "ngap": "DownlinkNASTransport",
                 "kind": "initiatingMessage",
                 "nas": "5GMMSecProtNASMessage", "nas_protected": True,
                 "nas_inner": "5GMMStatus", "nas_cause": None,
                 "unparsed": None},
                {"ts": 1000.5, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                 "ngap": "UplinkNASTransport",
                 "kind": "initiatingMessage",
                 "nas": "5GMMRegistrationRequest", "nas_protected": False,
                 "nas_inner": None,
                 "nas_cause": {"code": 91,
                               "name": "Payload was not forwarded"},
                 "unparsed": None},
            ],
            "procedures": [{
                "kind": "registration", "start_ts": 1000.0,
                "end_ts": 1000.5,
                "start_msg": "5GMMRegistrationRequest",
                "end_msg": "5GMMStatus",
                "outcome": "reject", "duration_ms": 500.0}]}],
        "unassociated": [
            {"ts": 999.0, "ngap": "NGSetupRequest", "unparsed": None}]},
        n4={"messages": [{
            "ts": 2000.0, "src_ip": "10.0.0.3", "dst_ip": "10.0.0.4",
            "src_port": 8805, "dst_port": 8805,
            "name": "PFCP Session Establishment Response", "seq": 193,
            "seid": 517, "cause": "Request accepted", "unparsed": None}],
            "procedures": [], "unpaired_requests": 0})


def test_load_capture_golden_fixtures():
    capture = golden()
    assert len(capture.n2["flows"]) == 3
    assert len(capture.n4["messages"]) == 16


def test_load_capture_n4_optional():
    capture = load_capture(FIXTURES / "golden_n2.json")
    assert capture.n4 is None


def test_load_capture_raises_on_missing_file():
    with pytest.raises(FileNotFoundError):
        load_capture(FIXTURES / "no_such_file.json")


def test_kpis():
    out = inspect_decoded_evidence(golden(), "kpis")
    assert out.startswith("Decode KPIs:")
    assert "procedure_success_rate=1.000" in out
    assert "attach_time_ms=110.685" in out


def test_flows_listing():
    out = inspect_decoded_evidence(golden(), "flows")
    assert out.startswith("Capture flows (3):")
    assert "flow 1: complete, 12 message(s)" in out
    assert "registration: accept, 36.0 ms" in out
    assert "pdu_session_est: accept, 2.4 ms" in out


def test_flow_detail():
    out = inspect_decoded_evidence(golden(), "flow:1")
    assert out.startswith(
        "Flow 1 (RAN-UE-NGAP-ID 1, AMF-UE-NGAP-ID 1, complete):")
    assert "[12] " in out  # 12 messages, all listed
    assert "InitialUEMessage  5GMMRegistrationRequest" in out
    assert "procedures:" in out
    assert "(5GMMRegistrationRequest -> 5GMMRegistrationAccept)" in out


def test_flow_message():
    out = inspect_decoded_evidence(golden(), "flow:1:2")
    assert out.startswith("Evidence flow:1:2:")
    assert "ts=1786968641.150" in out
    assert "10.53.0.11 -> 10.53.0.20" in out
    assert "ngap=DownlinkNASTransport (initiatingMessage)" in out
    assert "nas=5GMMAuthenticationRequest" in out
    assert "nas_inner=" not in out


def test_flow_message_protected_inner():
    out = inspect_decoded_evidence(mini_capture(), "flow:1:1")
    assert "nas=5GMMSecProtNASMessage (protected)" in out
    assert "nas_inner=5GMMStatus" in out


def test_flow_message_cause():
    out = inspect_decoded_evidence(mini_capture(), "flow:1:2")
    assert "nas_cause: Payload was not forwarded (#91)" in out
    listing = inspect_decoded_evidence(mini_capture(), "flow:1")
    assert "cause=Payload was not forwarded (#91)" in listing
    assert "5GMMStatus (protected)" in listing


def test_partial_flow_marked():
    listing = inspect_decoded_evidence(mini_capture(), "flows")
    assert "flow 1: partial, 2 message(s)" in listing
    detail = inspect_decoded_evidence(mini_capture(), "flow:1")
    assert "partial):" in detail


def test_unassociated_listing_and_view():
    listing = inspect_decoded_evidence(golden(), "unassociated")
    assert listing.startswith("Unassociated NGAP messages (2):")
    assert "NGSetupRequest" in listing
    out = inspect_decoded_evidence(golden(), "unassociated:1")
    assert out.startswith("Evidence unassociated:1:")
    assert "ngap=NGSetupRequest" in out


def test_n4_listing_and_view():
    listing = inspect_decoded_evidence(golden(), "n4")
    assert listing.startswith("N4 (PFCP) messages (16):")
    assert "PFCP Session Establishment Response" in listing
    out = inspect_decoded_evidence(golden(), "n4:6")
    assert out.startswith("Evidence n4:6:")
    assert "10.53.0.13:8805 -> 10.53.0.12:8805" in out
    assert "name=PFCP Session Establishment Response" in out
    assert "seid=517" in out
    assert 'cause="Request accepted"' in out


def test_n4_retransmit_marked():
    # A repeated (src, dst, seq) is the same unanswered request re-sent:
    # the listing and view mark it so evidence cites the first send.
    capture = DecodedCapture(n2={}, n4={"messages": [
        {"ts": 1.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
         "src_port": 8805, "dst_port": 8805,
         "name": "PFCP Session Establishment Request", "seq": 7,
         "seid": None, "cause": None, "unparsed": None},
        {"ts": 3.5, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
         "src_port": 8805, "dst_port": 8805,
         "name": "PFCP Session Establishment Request", "seq": 7,
         "seid": None, "cause": None, "unparsed": None},
        {"ts": 4.0, "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1",
         "src_port": 8805, "dst_port": 8805,
         "name": "PFCP Heartbeat Request", "seq": 9,
         "seid": None, "cause": None, "unparsed": None}]})
    listing = inspect_decoded_evidence(capture, "n4")
    lines = listing.splitlines()
    assert "(retransmit)" not in lines[1]  # the first send is unmarked
    assert ("[2] 3.500  10.0.0.1->10.0.0.2  "
            "PFCP Session Establishment Request  (retransmit)") in lines[2]
    assert "(retransmit)" not in lines[3]  # a fresh seq is not a retransmit
    assert "retransmit: true" in inspect_decoded_evidence(capture, "n4:2")
    assert "retransmit" not in inspect_decoded_evidence(capture, "n4:1")


def test_no_n4_capture_degrades():
    capture = load_capture(FIXTURES / "golden_n2.json")
    for handle in ("n4", "n4:1"):
        out = inspect_decoded_evidence(capture, handle)
        assert "no N4 capture loaded" in out


def test_unrecognized_handle_degrades():
    out = inspect_decoded_evidence(golden(), "bogus")
    assert 'unrecognized handle "bogus"' in out
    assert "flow:<id>" in out  # lists the expected handle space
    assert 'unrecognized handle "flow:x"' in \
        inspect_decoded_evidence(golden(), "flow:x")
    assert 'unrecognized handle "n4:x"' in \
        inspect_decoded_evidence(golden(), "n4:x")


def test_out_of_range_handles_degrades():
    assert "no flow 9 in the capture (3 flow(s))" in \
        inspect_decoded_evidence(golden(), "flow:9")
    assert "flow 1 has 12 message(s); no message 13" in \
        inspect_decoded_evidence(golden(), "flow:1:13")
    assert "flow 1 has 12 message(s); no message 0" in \
        inspect_decoded_evidence(golden(), "flow:1:0")
    assert "unassociated has 2 message(s); no message 5" in \
        inspect_decoded_evidence(golden(), "unassociated:5")
    assert "n4 has 16 message(s); no message 17" in \
        inspect_decoded_evidence(golden(), "n4:17")


def test_empty_capture_degrades():
    capture = DecodedCapture(n2={})
    assert inspect_decoded_evidence(capture, "flows") == "Capture flows (0):"
    assert inspect_decoded_evidence(capture, "flow:1") == \
        "inspect_decoded_evidence: no flow 1 in the capture (0 flow(s))"
    assert inspect_decoded_evidence(capture, "kpis") == "Decode KPIs:"


def sbi_capture():
    """A synthetic SBI export: one accepted request/response pair and one
    403 with ProblemDetails."""
    return DecodedCapture(n2={}, sbi={
        "messages": [
            {"ts": 1.0, "src_ip": "10.53.0.22", "dst_ip": "10.53.0.21",
             "src_port": 50001, "dst_port": 7777, "stream_id": 1,
             "direction": "request", "method": "GET",
             "path": "/nnssf-nsselection/v1/network-slice-information",
             "status": None, "body_len": 0, "service": "Nnssf_NSSelection",
             "name": "Nnssf_NSSelection", "problem_title": None,
             "problem_cause": None, "unparsed": None},
            {"ts": 1.5, "src_ip": "10.53.0.21", "dst_ip": "10.53.0.22",
             "src_port": 7777, "dst_port": 50001, "stream_id": 1,
             "direction": "response", "method": None, "path": None,
             "status": 403, "body_len": 57,
             "service": "Nnssf_NSSelection", "name": "Nnssf_NSSelection",
             "problem_title": "Cannot find NSI",
             "problem_cause": "SNSSAI_NOT_SUPPORTED", "unparsed": None},
            {"ts": 0.5, "src_ip": "10.53.0.20", "dst_ip": "10.53.0.23",
             "src_port": 50002, "dst_port": 7777, "stream_id": 1,
             "direction": "request", "method": "POST",
             "path": "/nudm-sdm/v1/supi", "status": None, "body_len": 0,
             "service": "Nudm_SDM", "name": "Nudm_SDM",
             "problem_title": None, "problem_cause": None, "unparsed": None},
        ],
        "procedures": [
            {"kind": "Nudm_SDM", "start_ts": 0.5, "end_ts": 0.6,
             "start_msg": "POST /nudm-sdm/v1/supi", "end_msg": "200",
             "outcome": "accept", "status": 200},
            {"kind": "Nnssf_NSSelection", "start_ts": 1.0, "end_ts": 1.5,
             "start_msg": "GET /nnssf-nsselection/v1/network-slice-information",
             "end_msg": "403", "outcome": "reject", "status": 403}],
        "unpaired_requests": 0})


def test_sbi_listing():
    out = inspect_decoded_evidence(sbi_capture(), "sbi")
    assert out.startswith("SBI (HTTP/2) messages (3):")
    assert "[1] 1.000  GET /nnssf-nsselection/v1/network-slice-information" \
        "  (Nnssf_NSSelection)" in out
    assert "[2] 1.500  -> 403  (Nnssf_NSSelection)  " \
        'problem="Cannot find NSI"  cause="SNSSAI_NOT_SUPPORTED"' in out
    assert "[3] 0.500  POST /nudm-sdm/v1/supi  (Nudm_SDM)" in out


def test_sbi_view_request_and_response():
    capture = sbi_capture()
    out = inspect_decoded_evidence(capture, "sbi:1")
    assert out.startswith("Evidence sbi:1:")
    assert "10.53.0.22:50001 -> 10.53.0.21:7777" in out
    assert "direction=request" in out
    assert "method=GET" in out
    assert "path=/nnssf-nsselection/v1/network-slice-information" in out
    assert "name=Nnssf_NSSelection" in out
    out = inspect_decoded_evidence(capture, "sbi:2")
    assert "direction=response" in out
    assert "status=403" in out
    assert 'problem_title="Cannot find NSI"' in out
    assert 'problem_cause="SNSSAI_NOT_SUPPORTED"' in out


def test_no_sbi_capture_degrades():
    capture = load_capture(FIXTURES / "golden_n2.json")
    for handle in ("sbi", "sbi:1"):
        out = inspect_decoded_evidence(capture, handle)
        assert "no SBI capture loaded" in out


def test_sbi_handle_bounds():
    capture = sbi_capture()
    assert "sbi has 3 message(s); no message 4" in \
        inspect_decoded_evidence(capture, "sbi:4")
    assert 'unrecognized handle "sbi:x"' in \
        inspect_decoded_evidence(capture, "sbi:x")


def test_load_capture_detects_merged_export(tmp_path):
    # the merged three-plane export embeds the plane sections: passed as
    # the N2 file it loads them without separate --n4/--sbi files
    merged = tmp_path / "merged.json"
    merged.write_text(json.dumps({
        "kpis": {}, "flows": [{"flow_id": 1, "messages": [],
                               "n4_refs": [0], "sbi_refs": [1]}],
        "unassociated": [],
        "n4": {"messages": [{"name": "PFCP Session Establishment Response",
                             "ts": 1.0}],
               "procedures": [], "unpaired_requests": 0},
        "sbi": {"messages": [{"ts": 0.5, "direction": "request",
                              "method": "POST", "path": "/x"}],
                "procedures": [], "unpaired_requests": 0}}))
    capture = load_capture(merged)
    assert capture.n2["flows"][0]["n4_refs"] == [0]
    assert capture.n4["messages"][0]["name"] == \
        "PFCP Session Establishment Response"
    assert capture.sbi["messages"][0]["method"] == "POST"


def test_explicit_plane_paths_win_over_embedded_sections(tmp_path):
    # a separate --n4/--sbi file takes precedence over a merged file's
    # embedded section
    merged = tmp_path / "merged.json"
    merged.write_text(json.dumps(
        {"flows": [], "n4": {"messages": [{"name": "embedded"}]}}))
    n4 = tmp_path / "n4.json"
    n4.write_text(json.dumps({"messages": [{"name": "explicit"}]}))
    capture = load_capture(merged, n4_path=n4)
    assert capture.n4["messages"][0]["name"] == "explicit"


def correlated_capture():
    """A merged-style capture: flow 1's refs link N4 message 2 and SBI
    message 1."""
    return DecodedCapture(n2={
        "flows": [{
            "flow_id": 1, "ran_ue_ngap_id": 1, "amf_ue_ngap_id": 1,
            "partial": False,
            "messages": [{"ts": 1.0, "src_ip": "10.0.0.1",
                          "dst_ip": "10.0.0.2",
                          "ngap": "InitialUEMessage"}],
            "procedures": [],
            "n4_refs": [1], "sbi_refs": [0]}],
        "unassociated": []},
        n4={"messages": [
            {"ts": 0.5, "name": "PFCP Session Establishment Request"},
            {"ts": 1.2, "src_ip": "10.53.0.13", "dst_ip": "10.53.0.12",
             "name": "PFCP Session Establishment Response", "seq": 1}],
            "procedures": [], "unpaired_requests": 0},
        sbi={"messages": [
            {"ts": 0.7, "direction": "request", "method": "POST",
             "path": "/nsmf-pdusession/v1/sm-contexts"}],
            "procedures": [], "unpaired_requests": 0})


def test_flow_detail_lists_correlated_plane_messages():
    out = inspect_decoded_evidence(correlated_capture(), "flow:1")
    assert "correlated N4 message(s) (1):" in out
    assert "[n4:2]" in out
    assert "PFCP Session Establishment Response" in out
    assert "correlated SBI message(s) (1):" in out
    assert "[sbi:1]" in out
    assert "POST /nsmf-pdusession/v1/sm-contexts" in out


def test_flow_detail_without_refs_omits_correlated_sections():
    out = inspect_decoded_evidence(mini_capture(), "flow:1")
    assert "correlated" not in out
