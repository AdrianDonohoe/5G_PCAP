"""Procedural memory: operator-authored Runbooks as committed Markdown
with small YAML frontmatter. Parsed and validated at load; matched to
the incident signature with the shared scorer shape (3 per shared
symptom key, 2 for same procedure, threshold 2, top 3, newest first);
the top matches are prepended deterministically before the proposer
call, and any {placeholder} resolution args bind from the incident's
evidence at proposal time. Groq-free (ADR-0002): parsing, matching and
binding are pure file I/O and dict lookups."""

from datetime import date
from pathlib import Path

import pytest

from _helpers import make_proposer

from dispatch.memory import EvidenceKey
from dispatch.proposal import run_proposal
from dispatch.runbook import (Runbook, bind_placeholders, load_runbooks,
                              match_runbooks, parse_runbook,
                              runbook_context)

REPO_ROOT = Path(__file__).resolve().parents[2]

EVENT = {"description": "UE1's PDU session establishment hangs."}
ROOT_CAUSE = "The UPF logged the request and never answered it."

BASE_YAML = """slug: restart-stuck-upf
title: Restart the UPF when it stops answering PFCP
procedure: n4_upf_timeout
added: 2026-08-29
symptoms:
  nf: upf
steps:
  - Confirm the UPF logged the request.
  - Restart the upf service.
resolution:
  action: restart_nf
  args:
    nf: "{nf}"
"""


def _write_yaml(tmp_path, body=BASE_YAML):
    path = tmp_path / "runbook.md"
    path.write_text(f"---\n{body}---\n")
    return path


# --- Parsing and validation ---

def test_parse_valid_runbook(tmp_path):
    rb = parse_runbook(_write_yaml(tmp_path))
    assert rb.slug == "restart-stuck-upf"
    assert rb.title == "Restart the UPF when it stops answering PFCP"
    assert rb.procedure == "n4_upf_timeout"
    assert rb.added == date(2026, 8, 29)
    assert [(s.key, s.value) for s in rb.symptoms] == [("nf", "upf")]
    assert rb.steps == ["Confirm the UPF logged the request.",
                        "Restart the upf service."]
    assert rb.resolution.action == "restart_nf"
    assert rb.resolution.args == {"nf": "{nf}"}


def test_parse_normalizes_literal_resolution_args_to_strings(tmp_path):
    body = BASE_YAML.replace('nf: "{nf}"', 'imsi: 999700000000001')
    body = body.replace("action: restart_nf", "action: reseed_subscriber")
    rb = parse_runbook(_write_yaml(tmp_path, body))
    assert rb.resolution.args == {"imsi": "999700000000001"}


def test_parse_missing_frontmatter_raises(tmp_path):
    (tmp_path / "runbook.md").write_text("just prose")
    with pytest.raises(ValueError, match="frontmatter"):
        parse_runbook(tmp_path / "runbook.md")


def test_parse_unclosed_frontmatter_raises(tmp_path):
    (tmp_path / "runbook.md").write_text("---\nslug: restart-stuck-upf\n")
    with pytest.raises(ValueError, match="closed"):
        parse_runbook(tmp_path / "runbook.md")


def test_parse_malformed_yaml_raises(tmp_path):
    (tmp_path / "runbook.md").write_text("---\nkey: [\n---\n")
    with pytest.raises(ValueError):
        parse_runbook(tmp_path / "runbook.md")


@pytest.mark.parametrize("old,new", [
    # The action must name one of the Executor's vocabulary actions.
    ("action: restart_nf", "action: reboot_the_lab"),
    # The resolution is required.
    ("\nresolution:", "\nno_resolution_here:"),
    # The frontmatter carries only the documented keys — a typo'd key
    # must fail loudly, never silently produce a runbook that never
    # matches.
    ("procedure: n4_upf_timeout\n", "procedure: n4_upf_timeout\nunrelated: x\n"),
    # Symptoms are a mapping of scalar key: value pairs.
    ("symptoms:\n  nf: upf", "symptoms:\n  nf: [upf]"),
    ("symptoms:\n  nf: upf", "symptoms: upf"),
    # Steps are ordered non-empty prose.
    ("  - Confirm the UPF logged the request.\n", "  - 42\n"),
    # The resolution args are a mapping.
    ('args:\n    nf: "{nf}"', "args: nf"),
])
def test_parse_rejects_invalid_frontmatter(tmp_path, old, new):
    with pytest.raises(ValueError):
        parse_runbook(_write_yaml(tmp_path, BASE_YAML.replace(old, new)))


def test_parse_rejects_empty_steps(tmp_path):
    body = BASE_YAML.replace(
        "steps:\n  - Confirm the UPF logged the request.\n"
        "  - Restart the upf service.\n", "steps: []\n")
    with pytest.raises(ValueError, match="steps"):
        parse_runbook(_write_yaml(tmp_path, body))


# --- Loading ---

def test_load_runbooks_skips_corrupt_files(tmp_path):
    _write_yaml(tmp_path)
    (tmp_path / "broken.md").write_text("not a runbook")
    assert [rb.slug for rb in load_runbooks(tmp_path)] \
        == ["restart-stuck-upf"]


def test_load_runbooks_missing_directory_returns_empty(tmp_path):
    assert load_runbooks(tmp_path / "nope") == []


def test_committed_runbooks_dir_holds_exactly_the_seed():
    # AC-5: exactly one seed Runbook, derived from the committed sample
    # incident record (the KPI NAS cause 38 run).
    assert [rb.slug for rb in load_runbooks(REPO_ROOT / "dispatch" / "runbooks")] \
        == ["nas-38-restart-smf"]


def test_seed_runbook_parses_and_targets_the_sample_incident():
    seed = parse_runbook(REPO_ROOT / "dispatch" / "runbooks"
                         / "nas-38-restart-smf.md")
    assert seed.slug == "nas-38-restart-smf"
    # The sample record's Procedure is none; the procedure-less runbook
    # scores +2 against other procedure-less events.
    assert seed.procedure == ""
    assert seed.added == date(2026, 8, 29)
    assert [(s.key, s.value) for s in seed.symptoms] == [("flow_id", 1)]
    assert seed.resolution.action == "restart_nf"
    # The record proposed the literal {"nf": "smf"} — and KPI evidence
    # carries only flow_id keys, so a {nf} placeholder could never bind.
    assert seed.resolution.args == {"nf": "smf"}
    assert seed.steps  # ordered prose from the record's narrative


# --- Matching: the shared scorer shape ---

def _runbook(slug, procedure=None, symptoms=(), added=None):
    return Runbook(slug=slug, title=f"Runbook {slug}",
                   procedure=procedure,
                   symptoms=[EvidenceKey(key=key, value=value)
                             for key, value in symptoms],
                   steps=["a step"],
                   resolution={"action": "restart_nf",
                               "args": {"nf": "{nf}"}},
                   added=added)


EVIDENCE = [{"source": "log", "keys": {"nf": "upf", "teid": "0x1"}}]


def test_match_scores_shared_symptom_keys_and_procedure():
    a = _runbook("a", procedure="n4_upf_timeout",
                 symptoms=(("nf", "upf"),))
    # 3 (symptom) + 2 (procedure) = 5.
    assert match_runbooks([a], {"procedure": "n4_upf_timeout"},
                          EVIDENCE) == [a]
    # 3 alone still clears the threshold of 2.
    assert match_runbooks([a], {"procedure": "other"}, EVIDENCE) == [a]
    # 2 (procedure alone) clears it too.
    b = _runbook("b", procedure="n4_upf_timeout",
                 symptoms=(("nf", "smf"),))
    assert match_runbooks([b], {"procedure": "n4_upf_timeout"},
                          EVIDENCE) == [b]
    # Below the threshold: no match.
    c = _runbook("c", procedure="other", symptoms=(("nf", "smf"),))
    assert match_runbooks([c], {"procedure": "n4_upf_timeout"},
                          EVIDENCE) == []


def test_match_ranks_by_score_then_newest_then_slug():
    two = _runbook("two", symptoms=(("nf", "upf"), ("teid", "0x1")))   # 6
    one_old = _runbook("one-old", symptoms=(("nf", "upf"),),
                       added=date(2025, 1, 1))                         # 3
    one_new = _runbook("one-new", symptoms=(("nf", "upf"),),
                       added=date(2026, 1, 1))                         # 3
    proc = _runbook("proc", procedure="n4_upf_timeout",
                    symptoms=(("nf", "smf"),))                         # 2
    event = {"procedure": "n4_upf_timeout"}
    assert [r.slug for r in match_runbooks(
        [proc, one_old, one_new, two], event, EVIDENCE)] \
        == ["two", "one-new", "one-old"]


def test_match_top_three_cap_and_slug_tiebreak():
    runbooks = [_runbook(f"r{i}", procedure="n4_upf_timeout")
                for i in range(5)]
    # All score 2 (procedure) with no added dates: the tie breaks by
    # slug, deterministically.
    assert [r.slug for r in match_runbooks(
        runbooks, {"procedure": "n4_upf_timeout"}, [])] \
        == ["r0", "r1", "r2"]


def test_match_normalizes_empty_procedure():
    # A runbook derived from a procedure-less incident (like the seed)
    # scores +2 against other procedure-less events.
    seed = _runbook("seed", procedure="", symptoms=(("flow_id", 1),))
    assert [r.slug for r in match_runbooks([seed],
                                           {"procedure": None}, [])] \
        == ["seed"]


def test_match_coerces_key_value_types():
    rb = _runbook("r", symptoms=(("flow_id", "1"),))
    assert match_runbooks([rb], {}, [{"keys": {"flow_id": 1}}]) == [rb]


# --- Context rendering ---

def test_runbook_context_renders_title_steps_resolution_and_keys():
    rb = _runbook("restart-stuck-upf", procedure="n4_upf_timeout",
                  symptoms=(("nf", "upf"),))
    text = runbook_context([rb], EVIDENCE, total=3)
    assert "Runbooks retrieved from procedural memory (1 of 3 Runbook(s)):" \
        in text
    assert "Runbook restart-stuck-upf" in text
    assert "Confirm the UPF logged the request" not in text  # steps differ
    assert "a step" in text
    assert 'restart_nf {"nf": "{nf}"}' in text
    assert "Evidence keys: nf=upf, teid=0x1" in text


# --- Placeholder binding ---

def test_bind_placeholders_substitutes_from_evidence():
    assert bind_placeholders({"nf": "{nf}"}, EVIDENCE) == {"nf": "upf"}
    # Literal values pass through untouched.
    assert bind_placeholders({"imsi": "999700000000001"}, EVIDENCE) \
        == {"imsi": "999700000000001"}
    assert bind_placeholders({"n": 1}, EVIDENCE) == {"n": 1}


def test_bind_placeholders_first_occurrence_wins():
    evidence = [{"keys": {"nf": "upf"}}, {"keys": {"nf": "smf"}}]
    assert bind_placeholders({"nf": "{nf}"}, evidence) == {"nf": "upf"}


def test_bind_placeholders_unknown_key_raises():
    with pytest.raises(ValueError, match="no evidence key"):
        bind_placeholders({"nf": "{missing}"}, EVIDENCE)


# --- run_proposal: matching, prepending, binding ---

def test_run_proposal_prepends_matching_runbook_before_the_proposer_call():
    rb = _runbook("restart-stuck-upf", procedure="n4_upf_timeout",
                  symptoms=(("nf", "upf"),))
    calls = []

    def propose(incident, root_cause):
        calls.append(incident)
        return {"action": "restart_nf", "args": {"nf": "upf"},
                "justification": "j"}

    assert run_proposal(EVENT, ROOT_CAUSE, proposer=propose,
                        runbooks=[rb], evidence=EVIDENCE) \
        == {"action": "restart_nf", "args": {"nf": "upf"},
            "justification": "j"}
    assert calls[0].startswith(
        "Runbooks retrieved from procedural memory")
    assert EVENT["description"] in calls[0]


def test_run_proposal_without_matching_runbook_is_untouched():
    rb = _runbook("r", procedure="other", symptoms=(("nf", "smf"),))
    calls = []

    def propose(incident, root_cause):
        calls.append(incident)
        return {"action": "observe_only", "args": {},
                "justification": "watch and re-run the capture later"}

    assert run_proposal(EVENT, ROOT_CAUSE, proposer=propose,
                        runbooks=[rb], evidence=EVIDENCE)["action"] \
        == "observe_only"
    assert calls == [EVENT["description"]]


def test_run_proposal_without_runbooks_seam_is_untouched():
    calls = []

    def propose(incident, root_cause):
        calls.append(incident)
        return {"action": "observe_only", "args": {},
                "justification": "watch and re-run the capture later"}

    run_proposal(EVENT, ROOT_CAUSE, proposer=propose)
    assert calls == [EVENT["description"]]


def test_run_proposal_binds_placeholder_args_from_evidence():
    def propose(incident, root_cause):
        return {"action": "restart_nf", "args": {"nf": "{nf}"},
                "justification": "j"}

    assert run_proposal(EVENT, ROOT_CAUSE, proposer=propose,
                        runbooks=[], evidence=EVIDENCE) \
        == {"action": "restart_nf", "args": {"nf": "upf"},
            "justification": "j"}


def test_run_proposal_unbound_placeholder_yields_no_proposal():
    def propose(incident, root_cause):
        return {"action": "restart_nf", "args": {"nf": "{missing}"},
                "justification": "j"}

    assert run_proposal(EVENT, ROOT_CAUSE, proposer=propose,
                        evidence=EVIDENCE) is None


def test_run_proposal_placeholder_binding_keeps_the_vocabulary_checks():
    # Binding never rescues an invalid selection: the vocabulary check
    # still rejects it.
    def propose(incident, root_cause):
        return {"action": "reboot_the_lab", "args": {"nf": "{nf}"},
                "justification": "j"}

    assert run_proposal(EVENT, ROOT_CAUSE, proposer=propose,
                        evidence=EVIDENCE) is None


def test_run_proposal_matching_runbook_keeps_stub_seam_shape():
    # The proposer seam is unchanged: it still receives exactly
    # (incident, root_cause) — the runbook context rides inside the
    # incident string.
    rb = _runbook("r", procedure="n4_upf_timeout",
                  symptoms=(("nf", "upf"),))

    def propose(incident, root_cause):
        assert root_cause == ROOT_CAUSE
        return {"action": "observe_only", "args": {}, "justification": "j"}

    run_proposal(EVENT, ROOT_CAUSE, proposer=propose, runbooks=[rb],
                 evidence=EVIDENCE)
