"""Post-incident report writer tests: deterministic template rendering over
synthetic saved runs and captures, plus one real-corpus spec-context check.

Per ADR-0002 the suite stays cheap: fixture-corpus tests build a tiny
SpecGraph in tmp_path (never touching the real cache), and the one
real-corpus case shares a session-scoped build (~3 s) over the committed
chunks.jsonl with its cache in tmp. No models, no network, no Groq.
"""

import json

import pytest

from triage.evidence import DecodedCapture
from triage.report import build_report, write_report
from triage.specgraph import SpecGraph
from triage.specrag import CHUNKS

SPEC_TITLES = {"24501": "TS 24.501"}


def write_corpus(path, chunks):
    path.write_text("".join(json.dumps(c) + "\n" for c in chunks))


def chunk(spec, clause, heading, breadcrumb, body):
    return {"spec": spec, "title": SPEC_TITLES[spec], "token": "j70",
            "version": "V19.7.0", "clause": clause, "heading": heading,
            "breadcrumb": breadcrumb, "chars": len(body),
            "text": (f"{SPEC_TITLES[spec]} V19.7.0 | "
                     f"{clause}\t{heading}\n{body}")}


GMM_CAUSE_BODY = (
    "The purpose of the 5GMM cause information element is to indicate why\n"
    "a 5GMM request from the UE was rejected by the network.\n"
    "0 | 0 | 0 | 1 | 0 | 1 | 0 | 1 |  | Synch failure\n"
    "0 | 0 | 0 | 1 | 0 | 1 | 1 | 0 |  | Congestion\n"
    "0 | 0 | 0 | 1 | 0 | 1 | 1 | 1 |  | Semantically incorrect message\n"
    "0 | 0 | 0 | 1 | 1 | 0 | 0 | 0 |  | Invalid mandatory information\n"
    "0 | 0 | 0 | 1 | 1 | 0 | 0 | 1 |  | Conditional IE error\n"
    "0 | 0 | 0 | 1 | 1 | 0 | 1 | 0 |  | Not authorized for this PLMN\n"
    "0 | 0 | 0 | 1 | 1 | 0 | 1 | 1 |  | N1 mode not allowed\n"
    "0 | 1 | 1 | 0 | 1 | 1 | 1 | 1 |  | Protocol error, unspecified\n"
)

GSM_CAUSE_BODY = (
    "0 | 1 | 0 | 0 | 0 | 0 | 1 | 1 |  | Insufficient resources for "
    "specific slice and DNN\n"
)

MSG_TABLE_BODY = (
    "0 | 1 | 0 | 1 | 0 | 1 | 1 | 0 |  | 5GMM status\n"
    "0 | 1 | 0 | 1 | 1 | 1 | 0 | 0 |  | Authentication failure\n"
)

ABNORMAL_BODY = (
    "Upon receiving an AUTHENTICATION FAILURE or a REGISTRATION REJECT\n"
    "message with a Synch failure indication, the UE shall consider the\n"
    "procedure failed.\n"
)


def tiny_chunks():
    return [
        chunk("24501", "9.11.3.2", "5GMM cause", [
            "9\tGeneral message format and information elements coding",
            "9.11\tOther information elements",
            "9.11.3\t5GS mobility management (5GMM) information elements"],
            GMM_CAUSE_BODY),
        chunk("24501", "9.11.4.2", "5GSM cause", [
            "9\tGeneral message format and information elements coding",
            "9.11\tOther information elements",
            "9.11.4\t5GS session management (5GSM) information elements"],
            GSM_CAUSE_BODY),
        chunk("24501", "9.7", "Message type", [
            "9\tMessage functional definitions and content"],
            MSG_TABLE_BODY),
        chunk("24501", "5.4.1.3.7", "Abnormal cases in the UE", [
            "5\tNAS signalling procedures", "5.4\tSecurity procedures"],
            ABNORMAL_BODY),
    ]


@pytest.fixture
def graph(tmp_path):
    corpus = tmp_path / "chunks.jsonl"
    write_corpus(corpus, tiny_chunks())
    g = SpecGraph(corpus_path=corpus, cache_dir=tmp_path / "cache")
    g.ensure()
    return g


@pytest.fixture(scope="session")
def real_graph(tmp_path_factory):
    graph = SpecGraph(corpus_path=CHUNKS,
                      cache_dir=tmp_path_factory.mktemp("report-specgraph"))
    graph.ensure()
    return graph


def synthetic_capture(n4=None):
    return DecodedCapture(n2={
        "kpis": {"attach_time_ms": 4283, "procedure_success_rate": 0.71},
        "flows": [{
            "flow_id": 1,
            "messages": [
                {"ts": 10.0, "nas_inner": "5GMMRegistrationRequest"},
                {"ts": 12.345, "nas_inner": "5GMMAuthenticationFailure",
                 "nas_cause": {"code": 21, "name": "Synch failure"}},
                {"ts": 12.481, "nas_inner": "5GMMRegistrationReject",
                 "nas_cause": {"code": 111,
                               "name": "Protocol error, unspecified"}},
            ],
        }],
    }, n4=n4)


def saved_run(**overrides):
    result = {
        "flow_id": 1,
        "procedure": "Registration",
        "shape": "explicit reject",
        "detail": "cause code(s) observed: #21, #111",
        "episode": {
            "incident_type": "auth_failure",
            "narrative": "The AMF rejected the UE: MAC mismatch in "
                         "authentication.",
            "cited_evidence": [
                {"message": "5GMMAuthenticationFailure", "cause": 21,
                 "ts": 12.345},
                {"message": "5GMMRegistrationReject", "cause": 111,
                 "ts": 12.481},
            ],
            "created_at": "2026-08-18T00:00:00Z",
        },
        "reward": 0.87,
        "rollouts": 4,
        "trajectory": [
            ["inspect flow:1",
             "Flow 1 (RAN-UE-NGAP-ID 1, AMF-UE-NGAP-ID 2, complete):\n"
             "  [1] 12.345s  ..."],
            ["spec \"5GMM cause #21\"",
             "3GPP spec retrieval for \"5GMM cause #21\" (2 hit(s)):"],
            ["finalize {...}",
             "finalize accepted: hypothesis grounded in 2 evidence "
             "item(s)."],
        ],
        "memory_wrote": True,
    }
    result.update(overrides)
    return result


EXPECTED_SINGLE = """\
# Post-incident report — auth_failure

**Flow:** 1 — Registration, explicit reject
**Incident detail:** cause code(s) observed: #21, #111
**Hypothesis:** auth_failure (reward 0.87, 4 rollouts)

## Root cause
The AMF rejected the UE: MAC mismatch in authentication.

## Evidence
- [verified] 5GMMAuthenticationFailure @ 12.345s — cause #21
- [verified] 5GMMRegistrationReject @ 12.481s — cause #111

## Timeline (flow 1)
[1] 10.000s  5GMMRegistrationRequest
[2] 12.345s  5GMMAuthenticationFailure  cause #21 (Synch failure)
[3] 12.481s  5GMMRegistrationReject  cause #111 (Protocol error, unspecified)

## Capture KPIs
attach_time_ms: 4283 | procedure_success_rate: 0.71

## Search path
[1] inspect flow:1 -> Flow 1 (RAN-UE-NGAP-ID 1, AMF-UE-NGAP-ID 2, complete):
[2] spec "5GMM cause #21" -> 3GPP spec retrieval for "5GMM cause #21" (2 hit(s)):
[3] finalize {...} -> finalize accepted: hypothesis grounded in 2 evidence item(s).

## Memory
new Episode written (auth_failure)
"""


# --- template rendering ----------------------------------------------


def test_single_incident_byte_exact():
    report = build_report([saved_run()], synthetic_capture())
    assert report == EXPECTED_SINGLE


def test_zero_incidents():
    report = build_report([], synthetic_capture())
    assert report == ("# Post-incident report — no incidents\n\n"
                      "No failed Incidents to report.\n")


def test_multi_incident_file():
    second = saved_run(
        flow_id=2,
        episode={
            "incident_type": "registration_reject",
            "narrative": "UDM says no: IMSI unknown.",
            "cited_evidence": [
                {"message": "5GMMRegistrationReject", "cause": 111,
                 "ts": 12.481},
            ],
        },
        reward=0.55, rollouts=6)
    report = build_report([saved_run(), second], synthetic_capture())
    assert report.startswith("# Post-incident report — 2 incidents")
    assert "| 1 | 1 | auth_failure | 0.87 | 4 |" in report
    assert "| 2 | 2 | registration_reject | 0.55 | 6 |" in report
    assert "## Incident 1 — auth_failure — flow 1" in report
    assert "## Incident 2 — registration_reject — flow 2" in report
    assert "### Root cause" in report
    assert "**Incident detail:** cause code(s) observed: #21, #111" in report
    # the overview table carries flow/hypothesis; no per-incident header
    assert "**Flow:**" not in report


def test_no_hypothesis():
    report = build_report(
        [saved_run(episode=None, reward=0.0, rollouts=10, trajectory=[],
                   memory_wrote=False)],
        synthetic_capture())
    assert report.startswith("# Post-incident report — no hypothesis "
                             "(flow 1)")
    assert "No hypothesis: the LATS search completed no finalize." in report
    assert "(none cited)" in report
    assert "(no trajectory — the search exhausted its rollouts)" in report
    assert "no Episode written (no hypothesis)" in report
    assert "## Spec context" not in report
    assert "## Timeline (flow 1)" in report
    assert "attach_time_ms: 4283" in report


def test_minimal_result_renders():
    report = build_report([{"flow_id": 1}], synthetic_capture())
    assert "no hypothesis (flow 1)" in report
    assert "(trajectory not recorded in this results file)" in report


def test_invalid_episode_all_unverified():
    result = saved_run(episode={
        "narrative": "Raw narrative from a corrupt file.",
        "cited_evidence": [
            {"message": "5GMMAuthenticationFailure", "cause": 21,
             "ts": 12.345},
        ],
    })
    report = build_report([result], synthetic_capture())
    assert "no hypothesis (flow 1)" in report
    assert "Raw narrative from a corrupt file." in report
    assert "- [unverified] 5GMMAuthenticationFailure @ 12.345s — cause #21" \
        in report
    assert "## Spec context" not in report


# --- evidence verification -------------------------------------------


def test_wrong_ts_unverified():
    result = saved_run(episode={
        "incident_type": "auth_failure",
        "narrative": "x.",
        "cited_evidence": [
            {"message": "5GMMAuthenticationFailure", "cause": 21, "ts": 13.0},
        ],
    })
    report = build_report([result], synthetic_capture())
    assert "- [unverified] 5GMMAuthenticationFailure @ 13.000s — cause #21" \
        in report


def test_wrong_cause_unverified():
    result = saved_run(episode={
        "incident_type": "auth_failure",
        "narrative": "x.",
        "cited_evidence": [
            {"message": "5GMMAuthenticationFailure", "cause": 22,
             "ts": 12.345},
        ],
    })
    report = build_report([result], synthetic_capture())
    assert "- [unverified] 5GMMAuthenticationFailure @ 12.345s — cause #22" \
        in report


def test_n4_citation_needs_n4_loaded():
    n4 = {"messages": [{"name": "PFCP Session Establishment Response",
                        "ts": 5.0}]}
    result = saved_run(episode={
        "incident_type": "pdu_session_timeout",
        "narrative": "x.",
        "cited_evidence": [
            {"message": "PFCP Session Establishment Response", "cause": None,
             "ts": 5.0},
        ],
    })
    with_n4 = build_report([result], synthetic_capture(n4=n4))
    assert "- [verified] PFCP Session Establishment Response @ 5.000s" \
        in with_n4
    without = build_report([result], synthetic_capture(n4=None))
    assert "- [unverified] PFCP Session Establishment Response @ 5.000s" \
        in without


# --- spec context ----------------------------------------------------


def test_spec_context_from_tiny_graph(graph):
    report = build_report([saved_run()], synthetic_capture(), graph=graph)
    assert "## Spec context" in report
    assert 'entity 5GMM cause #21 "Synch failure"' in report
    assert "defined_in: 5GMM cause IE (clause 9.11.3.2)" in report
    # the section sits between Evidence and Timeline
    assert report.index("## Spec context") < \
        report.index("## Timeline (flow 1)")


def test_spec_context_omitted_without_graph():
    report = build_report([saved_run()], synthetic_capture())
    assert "## Spec context" not in report


def test_ngap_evidence_skips_cause_query(graph):
    # A cause on an NGAP-named message must not resolve to a 5GMM cause
    result = saved_run(episode={
        "incident_type": "registration_reject",
        "narrative": "x.",
        "cited_evidence": [
            {"message": "InitialContextSetupFailure", "cause": 21,
             "ts": 12.345},
        ],
    })
    report = build_report([result], synthetic_capture(), graph=graph)
    assert "entity 5GMM cause #21" not in report


def test_5gsm_protocol_inference(graph):
    result = saved_run(episode={
        "incident_type": "pdu_session_reject_other",
        "narrative": "x.",
        "cited_evidence": [
            {"message": "5GSMPDUSessionReject", "cause": 67, "ts": 12.345},
        ],
    })
    report = build_report([result], synthetic_capture(), graph=graph)
    assert "entity 5GSM cause #67" in report


def test_decoder_form_message_resolution(graph):
    result = saved_run(episode={
        "incident_type": "pdu_session_reject_slice",
        "narrative": "x.",
        "cited_evidence": [
            {"message": "5GMMStatus", "cause": None, "ts": 12.345},
        ],
    })
    report = build_report([result], synthetic_capture(), graph=graph)
    assert "entity 5GMM status" in report


def test_spec_blocks_deduped_and_capped(graph):
    # 5GMM-prefixed names that resolve to no message entity: the protocol
    # prefix lets the cause query through; the message query fails.
    cited = [{"message": f"5GMMUnresolvable{i}", "cause": 21 + i,
              "ts": 12.345} for i in range(7)]
    cited.append({"message": "5GMMUnresolvable0", "cause": 21,
                  "ts": 12.345})
    cited.append({"message": "5GMMStatus", "cause": None, "ts": 12.345})
    result = saved_run(episode={
        "incident_type": "auth_failure",
        "narrative": "x.",
        "cited_evidence": cited,
    })
    report = build_report([result], synthetic_capture(), graph=graph)
    # 8 unique entities (7 causes + 1 message); 6 shown, the rest counted
    assert "entity 5GMM cause #26" in report
    assert "entity 5GMM cause #27" not in report
    assert "… and 2 more" in report


def test_real_corpus_spec_context(real_graph):
    report = build_report([saved_run()], synthetic_capture(),
                          graph=real_graph)
    assert "## Spec context" in report
    assert "entity 5GMM cause #21" in report


# --- timeline / KPIs / search path / memory ---------------------------


def test_timeline_missing_flow():
    report = build_report([saved_run(flow_id=99)], synthetic_capture())
    assert "(flow 99 not found in this capture)" in report


def test_timeline_cap_50():
    capture = DecodedCapture(n2={"flows": [{
        "flow_id": 1,
        "messages": [{"ts": float(i), "ngap": f"Msg{i}"}
                     for i in range(51)],
    }]})
    report = build_report([saved_run()], capture)
    assert "[50] 49.000s  Msg49" in report
    assert "[51] 50.000s" not in report
    assert "... (1 more not shown)" in report


def test_search_path_truncates_first_line():
    long_obs = "x" * 100
    result = saved_run(trajectory=[["inspect flows", long_obs + "\nmore"]])
    report = build_report([result], synthetic_capture())
    assert "[1] inspect flows -> " + "x" * 77 + "…" in report
    assert "\nmore" not in report


def test_search_path_empty_observation():
    result = saved_run(trajectory=[["topology", ""]])
    report = build_report([result], synthetic_capture())
    assert "[1] topology\n" in report


def test_old_saved_file_missing_trajectory_and_detail():
    result = saved_run()
    del result["trajectory"]
    del result["detail"]
    report = build_report([result], synthetic_capture())
    assert "(trajectory not recorded in this results file)" in report
    assert "**Incident detail:**" not in report


def test_kpi_curated_order_and_extras_dropped():
    capture = DecodedCapture(n2={"kpis": {
        "procedure_failures": 3, "attach_time_ms": 4283, "extra": "x"}})
    report = build_report([saved_run()], capture)
    assert "attach_time_ms: 4283 | procedure_failures: 3" in report
    assert "extra" not in report


def test_kpi_absent():
    report = build_report([saved_run()],
                          DecodedCapture(n2={"flows": []}))
    assert "(no KPIs in this capture)" in report


def test_memory_not_rewritten():
    report = build_report([saved_run(memory_wrote=False)],
                          synthetic_capture())
    assert "Episode already recorded (auth_failure) — not rewritten" \
        in report


def test_write_report_matches_build(tmp_path):
    out = tmp_path / "report.md"
    write_report([saved_run()], synthetic_capture(), out)
    assert out.read_text() == build_report([saved_run()],
                                           synthetic_capture())
