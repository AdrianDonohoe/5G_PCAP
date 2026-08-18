"""Spec graph tests: extraction rules on hand-written fixture corpora, plus
the real-corpus fixture eval that pins the incident queries.

Per ADR-0002 the suite stays cheap: every fixture-corpus test builds a tiny
SpecGraph in tmp_path (never touching the real cache), and the real-corpus
cases share one session-scoped build (~3 s) over the committed chunks.jsonl
with its cache in tmp. No fastembed, no Groq, no downloads.
"""

import json

import numpy as np
import pytest

from triage.specgraph import EntityRef, SpecGraph
from triage.specrag import CHUNKS, SpecIndex, query_3gpp_spec

SPEC_TITLES = {"24501": "TS 24.501", "38413": "TS 38.413",
               "29244": "TS 29.244"}


def write_corpus(path, chunks):
    path.write_text("".join(json.dumps(c) + "\n" for c in chunks))


def chunk(spec, clause, heading, breadcrumb, body):
    """One corpus chunk in the chunks.jsonl shape build() reads."""
    return {"spec": spec, "title": SPEC_TITLES[spec], "token": "j70",
            "version": "V19.7.0", "clause": clause, "heading": heading,
            "breadcrumb": breadcrumb, "chars": len(body),
            "text": (f"{SPEC_TITLES[spec]} V19.7.0 | "
                     f"{clause}\t{heading}\n{body}")}


# --- fixture corpora: one chunk family per dialect --------------------

NAS_5GMM_CAUSE_BODY = (
    "The purpose of the 5GMM cause information element is to indicate why\n"
    "a 5GMM request from the UE was rejected by the network.\n"
    "0 | 0 | 0 | 1 | 0 | 1 | 0 | 1 |  | Synch failure\n"
    "0 | 1 | 1 | 0 | 1 | 1 | 1 | 1 |  | Protocol error, unspecified\n"
    "0 | 1 | 0 | 0 | 0 | 0 | 1 | 1 |  | Insufficient resources for specific slice and DNN\n"
    "0 | 1 | 0 | 1 | 1 | 0 | 1 | 1 |  | DNN not supported or not subscribed in the slice\n"
    "0 | 1 | 0 | 1 | 1 | 0 | 1 | 0 |  | Payload was not forwarded\n"
    "0 | 1 | - | - | - | - | - | - |  | Reserved\n"
)

NAS_5GSM_CAUSE_BODY = (
    "The purpose of the 5GSM cause information element is to indicate why\n"
    "a 5GSM request was rejected.\n"
    "0 | 1 | 0 | 0 | 0 | 0 | 1 | 1 |  | Insufficient resources for specific slice and DNN\n"
)

NAS_9_7_BODY = (
    "Bits 8 7 6 5 4 3 2 1\n"
    "0 | 1 | 0 | 0 | 0 | 0 | 0 | 1 |  | Registration request\n"
    "0 | 1 | 0 | 0 | 0 | 0 | 1 | 0 |  | Registration accept\n"
    "0 | 1 | 0 | 0 | 0 | 0 | 1 | 1 |  | Registration complete\n"
    "0 | 1 | 0 | 0 | 0 | 1 | 0 | 0 |  | Registration reject\n"
    "0 | 1 | 0 | 1 | 0 | 1 | 1 | 0 |  | Authentication reject\n"
    "0 | 0 | 0 | 1 | 0 | 1 | 1 | 0 |  | 5GMM status\n"
    "1 | 1 | 0 | 1 | 0 | 1 | 1 | 0 |  | 5GSM status\n"
    "0 | 1 | 0 | 0 | 1 | 1 | 0 | 0 |  | Service request\n"
    "0 | 1 | 0 | 0 | 1 | 1 | 0 | 1 |  | Control plane service request\n"
    "0 | 1 | - | - | - | - | - | - |  | 5GS mobility management messages\n"
)

NAS_ABNORMAL_BODY = (
    "Upon receiving an AUTHENTICATION REJECT or a REGISTRATION REJECT\n"
    "message with a Synch failure indication, the UE shall consider PDU\n"
    "SESSION INACTIVE states; RAND, AUTN, and NSSAI handling follows.\n"
)


def nas_fixture():
    return [
        chunk("24501", "9.11.3.2", "5GMM cause", [
            "9\tGeneral message format and information elements coding",
            "9.11\tOther information elements",
            "9.11.3\t5GS mobility management (5GMM) information elements"],
            NAS_5GMM_CAUSE_BODY),
        chunk("24501", "9.11.4.2", "5GSM cause", [
            "9\tGeneral message format and information elements coding",
            "9.11\tOther information elements",
            "9.11.4\t5GS session management (5GSM) information elements"],
            NAS_5GSM_CAUSE_BODY),
        chunk("24501", "9.7", "Message type", [
            "9\tMessage functional definitions and content"],
            NAS_9_7_BODY),
        chunk("24501", "5.4.1.3.7", "Abnormal cases in the UE", [
            "5\tNAS signalling procedures",
            "5.4\tSecurity procedures",
            "5.4.1\tPrimary authentication and key agreement procedure",
            "5.4.1.3\tAbnormal cases",
            "5.4.1.3.7\tAbnormal cases in the UE"],
            NAS_ABNORMAL_BODY),
        chunk("24501", "5.5.1", "Registration procedure", [
            "5\tNAS signalling procedures",
            "5.5\tMobility management procedures"],
            "The registration procedure is used ...\n"),
    ]


NGAP_CAUSE_BODY = (
    "IE/Group Name | Presence | Range | IE type and reference | Semantics description\n"
    ">>Radio Network Layer Cause | M |  | ENUMERATED (Unspecified, Cell not available, No radio resources available in target cell, …) | \n"
    ">NAS |  |  | ENUMERATED (Normal release, Unspecified) | \n"
)

NGAP_9_4_3_BODY = (
    "\tINITIATING MESSAGE\t\tInitialUEMessage\n"
    "\tSUCCESSFUL OUTCOME\t\tInitialUEContextSetupResponse\n"
    "\tUNSUCCESSFUL OUTCOME\t\tInitialUEContextSetupFailure\n"
    "\tINITIATING MESSAGE\t\t\t&InitiatingMessage\n"
)


def ngap_fixture():
    return [
        chunk("38413", "9.3.1.2", "Cause", [
            "9\tElements for NGAP Communication",
            "9.3\tInformation Element Definitions",
            "9.3.1\tRadio Network Layer Related IEs"],
            NGAP_CAUSE_BODY),
        chunk("38413", "9.4.3", "Elementary Procedure Definitions", [
            "9\tElements for NGAP Communication",
            "9.4\tElementary Procedure Definitions"],
            NGAP_9_4_3_BODY),
    ]


PFCP_8_2_1_BODY_A = (
    "Table 8.2.1-1: Cause values\n"
    "Message Type | Cause value (decimal) | Meaning | Description\n"
    "Acceptance in a response | 1 | Request accepted (success) | Indicates that\n"
    "Acceptance in a response | 4-63 | Spare. | These values shall not be used\n"
)

PFCP_8_2_1_BODY_B = (
    "Rejection in a response | 64 | Request rejected (reason not specified) | Indicates that\n"
)


def pfcp_fixture():
    return [
        chunk("29244", "8.2.1", "Cause", [
            "8\tInformation Elements", "8.2\tInformation Element Types"],
            PFCP_8_2_1_BODY_A),
        chunk("29244", "8.2.1", "Cause", [
            "8\tInformation Elements", "8.2\tInformation Element Types"],
            PFCP_8_2_1_BODY_B),
        chunk("29244", "7.4.1.2", "Heartbeat Request", [
            "7\tPFCP message formats and procedures",
            "7.4\tPFCP Node related procedures",
            "7.4.1\tPFCP Association Setup Procedure"],
            "The PFCP Heartbeat Request message is sent periodically to "
            "check that the peer is alive.\n"),
    ]


FIXTURE_CHUNKS = nas_fixture() + ngap_fixture() + pfcp_fixture()


def make_graph(tmp_path, chunks=FIXTURE_CHUNKS):
    corpus = tmp_path / "chunks.jsonl"
    write_corpus(corpus, chunks)
    return corpus, SpecGraph(corpus_path=corpus, cache_dir=tmp_path / "cache")


@pytest.fixture
def graph(tmp_path):
    _, graph = make_graph(tmp_path)
    graph.ensure()
    return graph


def stub_embed(texts):
    # 1-dim all-ones vectors: every chunk scores 1.0, deterministic order
    return np.asarray([[1.0] for _ in texts], dtype=np.float32)


def zero_embed(texts):
    # Zero query vector -> q_norm 0 -> search() returns no hits
    return np.zeros((len(texts), 1), dtype=np.float32)


def make_index(tmp_path, corpus, embed=stub_embed, name="stub"):
    return SpecIndex(embed=embed, name=name, corpus_path=corpus,
                     index_dir=tmp_path / "index")


# --- fixture-corpus tests --------------------------------------------


def test_build_is_deterministic(tmp_path):
    corpus, g1 = make_graph(tmp_path)
    g1.ensure()
    g2 = SpecGraph(corpus_path=corpus, cache_dir=tmp_path / "cache2")
    g2.ensure()
    assert g1._cache_path().read_bytes() == g2._cache_path().read_bytes()


def test_clause_tree_from_breadcrumbs(graph):
    data = json.loads(graph._cache_path().read_text())
    by_id = {e["id"]: e for e in data["entities"]}
    # heading-only node (never itself a chunk) comes from breadcrumbs
    assert by_id["clause:24501:9.11.3"]["name"] == \
        "5GS mobility management (5GMM) information elements"
    edges = {(e["src"], e["dst"]): e for e in data["edges"]
             if e["kind"] == "contains"}
    assert edges[("clause:24501:9.11.3",
                  "clause:24501:9.11.3.2")]["exact"] is True
    assert edges[("clause:24501:9", "clause:24501:9.7")]["exact"] is True


def test_nas_cause_rows_parsed(graph):
    causes = {(e.protocol, e.value): e for e in graph._entities
              if e.type == "cause" and e.spec == "24501"}
    # 21, 111, 67, 91, 90 in the 5GMM table; 67 in the 5GSM table; the
    # "-"-row never became a cause
    assert len(causes) == 6
    c21 = causes[("5GMM", 21)]
    assert c21.display == "Synch failure"
    assert c21.id == "cause:24501:9.11.3.2:21"
    assert c21.value == 21 and c21.protocol == "5GMM"
    assert not c21.pattern_derived
    assert causes[("5GMM", 111)].display == "Protocol error, unspecified"
    assert causes[("5GMM", 91)].display == \
        "DNN not supported or not subscribed in the slice"
    assert causes[("5GMM", 90)].display == "Payload was not forwarded"
    # 67 exists in BOTH tables; the protocol prefix disambiguates
    assert causes[("5GMM", 67)].display == causes[("5GSM", 67)].display == \
        "Insufficient resources for specific slice and DNN"
    assert causes[("5GSM", 67)].clause == "9.11.4.2"


def test_pfcp_cause_rows_parsed(graph):
    causes = {e.value: e for e in graph._entities
              if e.type == "cause" and e.spec == "29244"}
    # the "4-63" range row is skipped; the second 8.2.1 chunk joins in
    assert set(causes) == {1, 64}
    assert causes[1].display == "Request accepted (success)"
    assert causes[64].display == \
        "Request rejected (reason not specified)"


def test_ngap_cause_enumerated_parsed(graph):
    causes = [e for e in graph._entities
              if e.type == "cause" and e.spec == "38413"]
    by_key = {(e.group, e.name): e for e in causes}
    assert len(causes) == 5  # 3 radio-network-layer + 2 NAS, "…" dropped
    assert by_key[("Radio Network Layer",
                   'NGAP cause "Cell not available"')].value is None
    assert ("Radio Network Layer", 'NGAP cause "Unspecified"') in by_key
    assert ("NAS", 'NGAP cause "Normal release"') in by_key
    assert all(e.value is None for e in causes)


def test_messages_filtered(graph):
    nas_names = {e.name for e in graph._entities
                 if e.type == "message" and e.spec == "24501"}
    # 9.7 rows; the two ALL-CAPS runs in the abnormal-cases text upgrade
    # their displays; noise runs never enter the vocabulary
    assert nas_names == {
        "Registration request", "Registration accept",
        "Registration complete", "REGISTRATION REJECT",
        "AUTHENTICATION REJECT", "5GMM status", "5GSM status",
        "Service request", "Control plane service request"}
    for noise in ("PDU SESSION INACTIVE", "RAND", "AUTN", "NSSAI",
                  "5GS mobility management messages"):
        assert noise not in nas_names
    # PFCP messages are heading-derived, not pattern-derived
    pfcp = [e for e in graph._entities
            if e.type == "message" and e.spec == "29244"]
    assert [m.name for m in pfcp] == ["Heartbeat Request"]
    assert not pfcp[0].pattern_derived
    # NGAP messages come from the 9.4.3 ASN.1 definitions
    ngap = [e for e in graph._entities
            if e.type == "message" and e.spec == "38413"]
    assert {m.name for m in ngap} == {
        "InitialUEMessage", "InitialUEContextSetupResponse",
        "InitialUEContextSetupFailure"}
    assert all(m.pattern_derived and m.clause == "9.4.3" for m in ngap)


def test_co_mentioned_edges(graph):
    data = json.loads(graph._cache_path().read_text())
    co = {(e["src"], e["dst"]): e for e in data["edges"]
          if e["kind"] == "co_mentioned"}
    m_auth = "message:24501:9.7:AUTHENTICATION REJECT"
    m_reg = "message:24501:9.7:REGISTRATION REJECT"
    c21 = "cause:24501:9.11.3.2:21"
    p541 = "procedure:24501:5.4.1"
    # the abnormal-cases chunk pairs the one cause with both messages and
    # the procedure, cross-type only
    assert len(co) == 5
    for pair in [(c21, m_auth), (c21, m_reg), (c21, p541),
                 (m_auth, p541), (m_reg, p541)]:
        assert co[pair]["exact"] is False
    for src, dst in co:
        assert src.split(":", 1)[0] != dst.split(":", 1)[0]


def test_defined_in_edges(graph):
    data = json.loads(graph._cache_path().read_text())
    edges = {(e["src"], e["dst"]): e for e in data["edges"]
             if e["kind"] == "defined_in"}
    assert edges[("cause:24501:9.11.3.2:21",
                  "ie:24501:9.11.3.2")]["exact"] is True
    assert edges[("cause:24501:9.11.4.2:67",
                  "ie:24501:9.11.4.2")]["exact"] is True
    assert edges[("cause:29244:8.2.1:64", "ie:29244:8.2.1")]["exact"] is True
    assert edges[("cause:38413:9.3.1.2:Radio Network Layer:Unspecified",
                  "ie:38413:9.3.1.2")]["exact"] is True
    # every cause has exactly one defined_in edge
    data_causes = {e["id"] for e in data["entities"]
                   if e["type"] == "cause"}
    assert {src for src, _ in edges} == data_causes


def test_resolve_cause_variants(graph):
    assert graph.resolve("cause #21").name == "5GMM cause #21"
    assert graph.resolve("cause 21").name == "5GMM cause #21"
    assert graph.resolve("cause=91").name == "5GMM cause #91"
    assert graph.resolve(
        "what does 5GMM cause #111 mean").name == "5GMM cause #111"
    ref = graph.resolve("5GSM cause 67")
    assert ref.name == "5GSM cause #67" and ref.clause == "9.11.4.2"
    # bare "cause 67" exists in both tables; the 5GMM table (9.11.3.2) wins
    assert graph.resolve("cause 67").clause == "9.11.3.2"
    # a cause-number query with no matching cause resolves to nothing
    assert graph.resolve("cause 9999") is None


def test_resolve_name_branch(graph):
    ref = graph.resolve("REGISTRATION REJECT")
    assert ref.type == "message" and ref.name == "REGISTRATION REJECT"
    # longest normalized key wins
    ref = graph.resolve("CONTROL PLANE SERVICE REQUEST")
    assert ref.name == "Control plane service request"
    # the decoder form shares its key with the spec form
    ref = graph.resolve("5GMMStatus")
    assert ref.type == "message" and ref.name == "5GMM status"
    ref = graph.resolve("5GMM STATUS #91")
    assert ref.type == "message" and ref.name == "5GMM status"
    # no cause number -> the IE
    ref = graph.resolve("5GMM cause")
    assert ref.type == "ie" and ref.name == "5GMM cause"
    ref = graph.resolve("registration procedure")
    assert ref.type == "procedure" and ref.name == "Registration procedure"
    assert graph.resolve("unrelated prose query") is None


def test_entity_block(graph):
    assert graph.entity_block(graph.resolve("cause #21")) == [
        'entity 5GMM cause #21 "Synch failure"',
        "  defined_in: 5GMM cause IE (clause 9.11.3.2)",
        "  co-mentioned: AUTHENTICATION REJECT, REGISTRATION REJECT",
    ]
    assert graph.entity_block(graph.resolve("AUTHENTICATION REJECT")) == [
        "entity AUTHENTICATION REJECT (message, from text)",
        "  co-mentioned: 5GMM cause #21",
    ]
    assert graph.entity_block(graph.resolve("5GMM cause")) == \
        ["entity 5GMM cause (IE)"]
    assert graph.entity_block(graph.resolve("registration procedure")) == \
        ["entity Registration procedure (procedure)"]
    # NGAP causes render their layer group
    ngap_cause = graph._by_id[
        "cause:38413:9.3.1.2:Radio Network Layer:Unspecified"]
    assert graph.entity_block(ngap_cause) == [
        'entity NGAP cause "Unspecified" (Radio Network Layer)',
        "  defined_in: Cause IE (clause 9.3.1.2)",
    ]
    # clause refs (unreachable via resolve) render clause + heading
    ref = EntityRef(type="clause", spec="24501", name="5GMM cause",
                    clause="9.11.3.2", id="clause:24501:9.11.3.2")
    assert graph.entity_block(ref) == ["entity 9.11.3.2 5GMM cause (clause)"]


def test_observation_entity_hit(tmp_path):
    corpus, graph = make_graph(tmp_path)
    index = make_index(tmp_path, corpus)
    obs = query_3gpp_spec("cause #21", top_k=2, index=index, graph=graph)
    lines = obs.split("\n")
    assert lines[0] == ('3GPP spec retrieval for "cause #21" '
                        "(2 hit(s); entity: 5GMM cause #21):")
    assert lines[1] == 'entity 5GMM cause #21 "Synch failure"'
    assert lines[2] == "  defined_in: 5GMM cause IE (clause 9.11.3.2)"
    assert lines[3] == "  co-mentioned: AUTHENTICATION REJECT, REGISTRATION REJECT"
    assert lines[4].startswith("[1] score=")


def test_observation_zero_hits_entity(tmp_path):
    corpus, graph = make_graph(tmp_path)
    index = make_index(tmp_path, corpus, embed=zero_embed, name="zero")
    obs = query_3gpp_spec("cause #21", top_k=2, index=index, graph=graph)
    lines = obs.split("\n")
    assert lines[0] == ('3GPP spec retrieval for "cause #21" '
                        "(0 hit(s); entity: 5GMM cause #21):")
    assert lines[1] == 'entity 5GMM cause #21 "Synch failure"'
    assert all(not line.startswith("[") for line in lines)


def test_observation_entity_miss_unchanged(tmp_path):
    corpus, graph = make_graph(tmp_path)
    index = make_index(tmp_path, corpus)
    with_graph = query_3gpp_spec("unrelated prose", top_k=2,
                                 index=index, graph=graph)
    without_graph = query_3gpp_spec("unrelated prose", top_k=2, index=index)
    assert with_graph == without_graph
    assert with_graph.startswith(
        '3GPP spec retrieval for "unrelated prose" (2 hit(s)):')
    assert "\n\n[1]" in with_graph  # blank line separates header from hits


def test_observation_graph_degrade(tmp_path):
    corpus, graph = make_graph(tmp_path)
    graph.ensure()  # build the cache, then corrupt it
    graph._cache_path().write_text("{oops")
    broken = SpecGraph(corpus_path=corpus, cache_dir=tmp_path / "cache")
    index = make_index(tmp_path, corpus)
    obs = query_3gpp_spec("cause #21", top_k=2, index=index, graph=broken)
    assert obs == query_3gpp_spec("cause #21", top_k=2, index=index)


def test_cache_rebuilt_when_corpus_changes(tmp_path):
    corpus, graph = make_graph(tmp_path, chunks=nas_fixture())
    graph.ensure()
    first_cache = graph._cache_path()
    write_corpus(corpus, FIXTURE_CHUNKS)
    second = SpecGraph(corpus_path=corpus, cache_dir=tmp_path / "cache")
    second.ensure()
    assert second._cache_path() != first_cache
    assert "clause:38413:9.3.1.2" not in graph._by_id
    assert "clause:38413:9.3.1.2" in second._by_id


def test_cache_reused_across_instances(tmp_path, monkeypatch):
    corpus, graph = make_graph(tmp_path)
    graph.ensure()
    monkeypatch.setattr(SpecGraph, "build",
                        lambda self: pytest.fail("cache not reused"))
    second = SpecGraph(corpus_path=corpus, cache_dir=tmp_path / "cache")
    second.ensure()
    assert second.resolve("cause #21").name == "5GMM cause #21"


# --- real-corpus fixture eval ----------------------------------------

FIXTURE_QUERIES = [
    ("cause #21", "5GMM cause #21", "Synch failure", "9.11.3.2"),
    ("5GMM cause #111", "5GMM cause #111", "Protocol error, unspecified",
     "9.11.3.2"),
    ("5GMM cause #7", "5GMM cause #7", "5GS services not allowed",
     "9.11.3.2"),
    ("5GMM STATUS #91", "5GMM status", None, "9.7"),
    ("5GSM cause 67", "5GSM cause #67",
     "Insufficient resources for specific slice and DNN", "9.11.4.2"),
    ("5GMM cause #90", "5GMM cause #90", "Payload was not forwarded",
     "9.11.3.2"),
    ("5GMM cause #91", "5GMM cause #91",
     "DNN not supported or not subscribed in the slice", "9.11.3.2"),
]


@pytest.fixture(scope="session")
def real_graph(tmp_path_factory):
    graph = SpecGraph(corpus_path=CHUNKS,
                      cache_dir=tmp_path_factory.mktemp("specgraph"))
    graph.ensure()
    return graph


@pytest.mark.parametrize("query,name,display,clause", FIXTURE_QUERIES)
def test_fixture_queries_resolve(real_graph, query, name, display, clause):
    ref = real_graph.resolve(query)
    assert ref is not None
    assert ref.name == name
    assert ref.clause == clause
    if display is not None:
        assert ref.display == display


def test_fixture_message_typing(real_graph):
    ref = real_graph.resolve("5GMM STATUS #91")
    assert ref.type == "message"
    assert ref.protocol == "5GMM"
    assert ref.pattern_derived


def test_fixture_observation_header(real_graph, tmp_path_factory):
    index = SpecIndex(embed=stub_embed, name="stub", corpus_path=CHUNKS,
                      index_dir=tmp_path_factory.mktemp("index"))
    obs = query_3gpp_spec("cause #21", top_k=2, index=index, graph=real_graph)
    assert obs.startswith('3GPP spec retrieval for "cause #21" '
                          "(2 hit(s); entity: 5GMM cause #21):")
