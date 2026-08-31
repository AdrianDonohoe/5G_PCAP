"""The CoALA feedback loop (spec #33, slice 3): closing a resolved,
executed incident drafts a Runbook proposal deterministically — no LLM
call — with the Episode's concrete args copied literally, into the
proposed-runbooks location, only when no committed Runbook already
covers the signature. The loop never touches committed Runbooks. All of
this is file I/O and string templates: Groq-free (ADR-0002)."""

import tempfile
from datetime import date
from pathlib import Path

from dispatch.learning import (confirmation_check, diff_new_file,
                               draft_filename, draft_text, matching_runbook,
                               outcome_section, write_draft)
from dispatch.memory import Episode, EvidenceKey
from dispatch.runbook import Runbook, parse_runbook


def _episode(**overrides):
    fields = dict(incident_id="inc-n4-upf-timeout-1",
                  procedure="n4_upf_timeout",
                  evidence_keys=[EvidenceKey(key="nf", value="upf")],
                  action="restart_nf", args={"nf": "upf"},
                  narrative="The UPF logged the request and never "
                            "answered it.",
                  justification="Restarting the UPF clears the stuck "
                                "session state.",
                  decision="approved-executed")
    fields.update(overrides)
    return Episode(**fields)


def _parsed(text):
    path = Path(tempfile.mkdtemp()) / "draft.md"
    path.write_text(text)
    return parse_runbook(path)


# --- The suggested confirmation check ---

EVENT = {"captures": {"n2": "/captures/n2.pcap", "sbi": "/captures/sbi.pcap",
                      "n4": "/captures/n4.pcap"}}


def test_confirmation_check_is_the_golden_kpi_comparison():
    # A KPI comparison on fresh post-remediation captures: the same
    # detect-kpi comparator, with the event's capture names.
    check = confirmation_check(
        {"action": "restart_nf", "args": {"nf": "upf"}}, EVENT,
        "/sandbox")
    assert check == "dispatch detect-kpi n2.pcap --sbi sbi.pcap " \
                    "--n4 n4.pcap"


def test_confirmation_check_for_rerun_capture_is_the_scenario_itself():
    check = confirmation_check(
        {"action": "rerun_capture", "args": {"scenario": "n4_upf_timeout"}},
        EVENT, "/sandbox")
    assert check == "bash /sandbox/capture.sh --scenario n4_upf_timeout"


def test_confirmation_check_without_captures_names_placeholders():
    check = confirmation_check(
        {"action": "reseed_subscriber", "args": {"imsi": "999700000000001"}},
        {}, "/sandbox")
    assert check == "dispatch detect-kpi <n2-capture>"


# --- The draft: deterministic, literal, traceable ---

def test_draft_filename_traces_to_the_episode():
    assert draft_filename(_episode()) == \
        "n4_upf_timeout-inc-n4-upf-timeout-1.md"


def test_draft_filename_without_procedure():
    ep = _episode(procedure=None, incident_id="inc-kpi-20a3050c")
    assert draft_filename(ep) == "none-inc-kpi-20a3050c.md"


def test_draft_text_roundtrips_through_the_runbook_parser():
    rb = _parsed(draft_text(_episode()))
    assert rb.slug == "n4_upf_timeout-inc-n4-upf-timeout-1"
    assert rb.procedure == "n4_upf_timeout"
    assert rb.added == date.today()
    assert [(s.key, s.value) for s in rb.symptoms] == [("nf", "upf")]
    assert rb.resolution.action == "restart_nf"
    # The concrete args are copied literally — never generalized to
    # {placeholder} form by the template (the operator does that at
    # promotion).
    assert rb.resolution.args == {"nf": "upf"}
    assert any("Diagnosis" in step for step in rb.steps)
    assert any("never answered" in step for step in rb.steps)


def test_draft_covers_every_vocabulary_action_with_literal_args():
    for action, args in [
        ("restart_nf", {"nf": "upf"}),
        ("revert_config", {"path": "core/config/upf.yaml"}),
        ("reseed_subscriber", {"imsi": "999700000000001"}),
        ("rerun_capture", {"scenario": "n4_upf_timeout"}),
    ]:
        rb = _parsed(draft_text(_episode(action=action, args=args)))
        assert rb.resolution.action == action
        assert rb.resolution.args == args


def test_draft_slug_matches_the_filename():
    ep = _episode()
    rb = _parsed(draft_text(ep))
    assert rb.slug == draft_filename(ep)[:-3]


def test_write_draft_lands_in_the_proposed_directory(tmp_path):
    path = write_draft(_episode(), tmp_path / "proposed")
    assert path == tmp_path / "proposed" / \
        "n4_upf_timeout-inc-n4-upf-timeout-1.md"
    assert path.read_text() == draft_text(_episode())


def test_diff_new_file_prefixed_with_plus_lines():
    diff = diff_new_file("---\nslug: x\n")
    assert "+++" in diff
    assert "+slug: x" in diff


# --- The skip rule: a matching committed Runbook means no draft ---

def _runbook(procedure=None, symptoms=()):
    return Runbook(slug="restart-stuck-upf", title="Restart a stuck UPF",
                   procedure=procedure,
                   symptoms=[EvidenceKey(key=key, value=value)
                             for key, value in symptoms],
                   steps=["a step"],
                   resolution={"action": "restart_nf",
                               "args": {"nf": "{nf}"}})


def test_matching_runbook_on_procedure():
    assert matching_runbook([_runbook(procedure="n4_upf_timeout")],
                            _episode())


def test_matching_runbook_on_symptom_keys():
    assert matching_runbook([_runbook(symptoms=(("nf", "upf"),))],
                            _episode())


def test_no_matching_runbook_with_an_unrelated_signature():
    assert not matching_runbook(
        [_runbook(procedure="other", symptoms=(("nf", "smf"),))],
        _episode())


def test_no_matching_runbook_in_an_empty_library():
    assert not matching_runbook([], _episode())


# --- The Outcome section for the Incident Record ---

def test_outcome_section_carries_verdict_evidence_and_check():
    section = outcome_section("resolved", "detect-kpi returned the "
                             "Golden baseline", "dispatch detect-kpi "
                             "n2.pcap")
    assert "## Outcome" in section
    assert "**resolved**" in section
    assert "detect-kpi returned the Golden baseline" in section
    assert "`dispatch detect-kpi n2.pcap`" in section
    assert "Closed at:" in section


def test_outcome_section_without_evidence_is_honest():
    section = outcome_section("unresolved", None, "dispatch detect-kpi")
    assert "**unresolved**" in section
    assert "(none)" in section
