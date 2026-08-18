"""Spec graph: a deterministic typed-entity graph over corpus/chunks.jsonl.

ADR-0003: the flat embedding index answers prose questions, but the
agent's exact queries ("what does 5GMM cause #111 mean") deserve the
entity answer: the cause row, the IE that defines it, the messages it
co-occurs with. The graph is extracted from the committed corpus by
deterministic rules -- per-spec-family profiles for the NAS/NGAP/PFCP/SBI
clause dialects -- cached under corpus/cache/ keyed on the corpus
sha256 (the same invalidation as the embedding index), and consulted
only to enrich query_3gpp_spec's observation, never to replace it.

Entity typing is honest: Clause/Procedure/IE/Cause entities derive from
clause structure and tables (exact); Message entities are derived from
name patterns in text and flagged pattern_derived. Edges: contains
(clause tree) and defined_in (cause -> the IE clause of its table) are
exact; co_mentioned edges are within-chunk co-occurrence inference and
are always labelled as such in agent output.
"""

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from triage.specrag import CHUNKS, CORPUS

MESSAGE_CAP = 8       # co-mentioned names shown before "… and N more"
WRAP = 80             # observation lines wrap at this width
CONTINUATION = 16     # continuation indent, aligned under "co-mentioned: "

# Cause-table dialects (verified against the pinned 19.x corpus):
# NAS tables are 10-cell rows: 8 bit cells (MSB first) + empty + name.
# PFCP rows are 4 cells [msg type, value, meaning, description] and
# include value ranges ("4-63") that are not causes.
# NGAP causes are ENUMERATED lists grouped by layer, with no numeric values.
NAS_CAUSE_TABLES = [("9.11.3.2", "5GMM"), ("9.11.4.2", "5GSM")]
PFCP_CAUSE_TABLE = ("8.2.1", "PFCP")
NGAP_CAUSE_TABLE = "9.3.1.2"

# "cause #21", "cause 21", "cause=91", "what does 5GMM cause #111 mean"
_CAUSE_RE = re.compile(
    r"\b(5GMM|5GSM|NGAP|PFCP)?\s*(?:cause\s+value|cause)\s*[=#]?\s*(\d+)\b",
    re.I)
# Procedure-section headings that are not procedures (verified against the
# breadcrumb-derived node set).
_PROCEDURE_STOPWORDS = ("general", "types of", "principles of", "overview",
                        "coordination", "list of")
_NGAP_HEADING_NOT_PROCEDURE = ("general", "successful operation",
                               "unsuccessful operation", "abnormal conditions")
# NAS message-name candidates: ALL-CAPS runs of 2+ words (single words like
# RAND, AUTN, NSSAI never form candidates), validated against the 9.7/8.x
# vocabulary below so "PDU SESSION INACTIVE" and IE names are dropped.
_NAS_MSG_RUN = re.compile(
    r"\b(?:5GMM|5GSM) [A-Z0-9]{2,}(?: [A-Z0-9]{2,})+\b"
    r"|\b[A-Z]{3,}(?: [A-Z0-9]{3,})+\b")
# NGAP message names come from the 9.4.3 ASN.1 definitions: one name per
# INITIATING MESSAGE / SUCCESSFUL OUTCOME / UNSUCCESSFUL OUTCOME line.
# Lines like "INITIATING MESSAGE\t\t\t&InitiatingMessage" fail the capture
# (the "&" breaks the pattern), which is exactly the generic type, not a name.
_NGAP_MSG_NAME = re.compile(
    r"\b(?:INITIATING MESSAGE|SUCCESSFUL OUTCOME|UNSUCCESSFUL OUTCOME)"
    r"\s+([A-Z][A-Za-z0-9]+)\b")
_PAREN = re.compile(r"\s*\(.*")  # "(UE originating de-registration)" noise
# SBI (TS 29.5xx) message names: service headings spell them directly
# ("Nudm_UEAuthentication Service API"), operation headings embed them
# ("Get service operation of Nnssf_NSSelection service"); body mentions
# of the same pattern are validated against that heading vocabulary.
_SBI_SPECS = ("29500", "29503", "29531")
_SBI_NAME = re.compile(
    r"\b(N[a-z]{2,}_[A-Z][A-Za-z0-9]*(?:_[A-Z][A-Za-z0-9]*)*)\b")

_TYPE_RANK = {"message": 0, "procedure": 1, "ie": 2}


def normalize(s: str) -> str:
    """Upper-cased alnum key: "Registration request" -> REGISTRATIONREQUEST,
    the decoder form "5GMMStatus" -> 5GMMSTATUS."""
    return re.sub(r"[^A-Z0-9]+", "", s.upper())


@dataclass(frozen=True)
class EntityRef:
    type: str  # clause | procedure | ie | cause | message
    spec: str
    name: str
    clause: str
    id: str
    protocol: str = ""
    pattern_derived: bool = False
    display: str = ""     # cause row name / message display name
    value: int = None     # cause value; None for NGAP (ENUMERATED only)
    group: str = ""       # NGAP cause layer ("Radio Network Layer", …)


def _body(chunk: dict) -> str:
    """Chunk text without its header line (title | clause<TAB>heading)."""
    return chunk["text"].split("\n", 1)[1]


def _clause_tree(chunks: list[dict]) -> tuple[dict, set]:
    """Nodes keyed (spec, clause) from chunk clauses + breadcrumb ancestors.

    Heading-only nodes (parents that are never themselves a chunk, e.g.
    the 8.2.x message parents of 38.413) come from breadcrumbs for free.
    Returns nodes {key: {"heading", "chunks": [indices]}} and the set of
    (parent, child) containment pairs.
    """
    nodes: dict = {}
    pairs: set = set()
    for i, chunk in enumerate(chunks):
        spec, clause = chunk["spec"], chunk["clause"]
        chain = [(part[0], part[1]) for part in
                 (bc.split("\t", 1) for bc in chunk["breadcrumb"])]
        chain.append((clause, chunk["heading"]))
        previous = None
        for cl, heading in chain:
            node = nodes.setdefault(
                (spec, cl), {"heading": heading, "chunks": []})
            if previous is not None:
                pairs.add((previous, (spec, cl)))
            previous = (spec, cl)
        # A chunk's own heading is authoritative over breadcrumb text.
        nodes[(spec, clause)]["heading"] = chunk["heading"]
        nodes[(spec, clause)]["chunks"].append(i)
    return nodes, pairs


def _split_row(line: str) -> list[str]:
    return [cell.strip() for cell in line.split("|")]


def _nas_bit_name(line: str) -> str | None:
    """10-cell NAS table row -> name; None for headers ("-"-bits) and prose.

    Used for both cause tables (name = cause display) and the 9.7
    message-type table (name = message name).
    """
    cells = _split_row(line)
    if (len(cells) != 10 or not all(c in ("0", "1") for c in cells[0:8])
            or cells[8] != "" or not cells[9]):
        return None
    return _PAREN.sub("", cells[9])


class SpecGraph:
    """Lazy deterministic spec graph over chunks.jsonl, cached on disk."""

    def __init__(self, corpus_path: Path = CHUNKS,
                 cache_dir: Path = CORPUS / "cache"):
        self.corpus_path = corpus_path
        self.cache_dir = cache_dir
        self._entities: list[EntityRef] | None = None
        self._by_id: dict = {}
        self._adjacency: dict = {}     # co_mentioned neighbors by entity id
        self._causes: list[EntityRef] = []
        self._names: list = []         # sorted (key, ref), longest key first
        self._ie_by_key: dict = {}     # (spec, clause) -> IE EntityRef

    def _cache_path(self) -> Path:
        sha = hashlib.sha256(self.corpus_path.read_bytes()).hexdigest()
        return self.cache_dir / f"specgraph-{sha[:16]}.json"

    def ensure(self) -> None:
        """Load the cached graph, or build it from the corpus once."""
        if self._entities is not None:
            return
        cache = self._cache_path()
        if cache.exists():
            data = json.loads(cache.read_text())
        else:
            data = self.build()
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(data, sort_keys=True, indent=2))
        self._entities = [EntityRef(**entity) for entity in data["entities"]]
        edges = data["edges"]
        self._by_id = {entity.id: entity for entity in self._entities}
        for edge in edges:
            if edge["kind"] != "co_mentioned":
                continue
            self._adjacency.setdefault(edge["src"], set()).add(
                self._by_id[edge["dst"]])
            self._adjacency.setdefault(edge["dst"], set()).add(
                self._by_id[edge["src"]])
        self._causes = [e for e in self._entities if e.type == "cause"]
        for entity in self._entities:
            if entity.type in _TYPE_RANK:
                self._names.append((normalize(entity.name), entity))
        self._names.sort(key=lambda pair: (
            -len(pair[0]), pair[0], _TYPE_RANK[pair[1].type]))
        self._ie_by_key = {(e.spec, e.clause): e for e in self._entities
                           if e.type == "ie"}

    def build(self) -> dict:
        """Extract the graph from the corpus, deterministically.

        Entities sorted by id, edges by (src, dst, kind), sort_keys JSON:
        two builds over the same corpus are byte-identical.
        """
        chunks = [json.loads(line) for line in
                  self.corpus_path.read_text().split("\n") if line]
        corpus_sha = hashlib.sha256(
            self.corpus_path.read_bytes()).hexdigest()
        nodes, pairs = _clause_tree(chunks)
        parents_of: dict = {}
        for parent, child in pairs:
            parents_of.setdefault(child, []).append(parent)

        entities: list[EntityRef] = []
        edges: set = set()

        # Clause entities: every tree node, chunk-bearing or heading-only.
        for (spec, clause), node in nodes.items():
            entities.append(EntityRef(
                type="clause", spec=spec, name=node["heading"], clause=clause,
                id=f"clause:{spec}:{clause}"))
            for parent in parents_of.get((spec, clause), ()):
                edges.add((f"clause:{parent[0]}:{parent[1]}",
                           f"clause:{spec}:{clause}", "contains", True))

        def chunk_bearing(spec: str, clause: str) -> bool:
            return bool(nodes.get((spec, clause), {}).get("chunks"))

        def heading_of(spec: str, clause: str) -> str:
            return nodes[(spec, clause)]["heading"]

        # IEs: chunk-bearing nodes of each dialect's IE section.
        for (spec, clause), node in nodes.items():
            is_ie = (
                (spec == "24501" and re.match(r"^9\.\d", clause)
                 and heading_of(spec, clause).lower() != "general")
                or (spec == "38413" and re.match(r"^9\.3\.\d+\.\d+$", clause))
                or (spec == "29244" and re.match(r"^8\.2\.\d+$", clause)))
            if is_ie and chunk_bearing(spec, clause):
                entities.append(EntityRef(
                    type="ie", spec=spec, name=node["heading"], clause=clause,
                    id=f"ie:{spec}:{clause}"))

        # Procedures: depth-3 nodes of each dialect's procedure sections.
        for (spec, clause), node in nodes.items():
            heading = node["heading"]
            is_procedure = (
                (spec == "24501" and re.match(r"^[56]\.\d+\.\d+$", clause)
                 and "procedure" in heading.lower()
                 and not any(word in heading.lower()
                             for word in _PROCEDURE_STOPWORDS))
                or (spec == "38413" and re.match(r"^8\.\d+\.\d+$", clause)
                    and heading.lower() not in _NGAP_HEADING_NOT_PROCEDURE)
                or (spec == "29244" and re.match(r"^6\.\d+\.\d+$", clause)
                    and "procedure" in heading.lower()))
            if is_procedure:
                entities.append(EntityRef(
                    type="procedure", spec=spec, name=heading, clause=clause,
                    id=f"procedure:{spec}:{clause}"))

        # Causes: per-dialect table rows over the joined clause bodies.
        for clause, protocol in NAS_CAUSE_TABLES:
            body = self._joined_body(chunks, "24501", clause)
            for line in body.split("\n"):
                name = _nas_bit_name(line)
                if name is None:
                    continue
                value = int("".join(_split_row(line)[0:8]), 2)
                entities.append(EntityRef(
                    type="cause", spec="24501",
                    name=f"{protocol} cause #{value}", clause=clause,
                    id=f"cause:24501:{clause}:{value}", protocol=protocol,
                    display=name, value=value))
        clause, protocol = PFCP_CAUSE_TABLE
        body = self._joined_body(chunks, "29244", clause)
        for line in body.split("\n"):
            cells = _split_row(line)
            if len(cells) != 4 or not cells[1] or not re.fullmatch(r"\d+",
                                                                   cells[1]):
                continue  # header, prose, and "4-63" range rows
            value = int(cells[1])
            entities.append(EntityRef(
                type="cause", spec="29244", name=f"PFCP cause #{value}",
                clause=clause, id=f"cause:29244:{clause}:{value}",
                protocol="PFCP", display=cells[2], value=value))
        body = self._joined_body(chunks, "38413", NGAP_CAUSE_TABLE)
        for line in body.split("\n"):
            if "ENUMERATED (" not in line:
                continue
            cells = _split_row(line)
            group = cells[0].lstrip(">").strip()
            if group.endswith(" Cause"):
                group = group[:-len(" Cause")]
            enumerated = [name.strip()
                          for name in re.search(r"ENUMERATED \((.*?)\)",
                                                line).group(1).split(",")]
            for name in (n for n in enumerated
                         if n and n != "…"):
                entities.append(EntityRef(
                    type="cause", spec="38413",
                    name=f'NGAP cause "{name}"', clause=NGAP_CAUSE_TABLE,
                    id=f"cause:38413:{NGAP_CAUSE_TABLE}:{group}:{name}",
                    protocol="NGAP", display=name, group=group))

        # Messages: per-dialect vocabularies, deduped by normalized key.
        # NAS: 9.7 message-type rows + 8.2.x/8.3.x parents (5GMM/5GSM
        # message definitions); an ALL-CAPS run in corpus text upgrades the
        # display name, but only names the vocabulary already knows.
        nas_messages: dict = {}   # key -> dict(display, clause, protocol)
        body = self._joined_body(chunks, "24501", "9.7")
        for line in body.split("\n"):
            cells = _split_row(line)
            name = _nas_bit_name(line)
            if name is None:
                continue
            protocol = "5GMM" if cells[0] == "0" else "5GSM"
            nas_messages[normalize(name)] = {
                "display": name, "clause": "9.7", "protocol": protocol}
        for (spec, clause), node in nodes.items():
            if spec != "24501" or not re.match(r"^8\.[23]\.\d+$", clause):
                continue
            name = _PAREN.sub("", node["heading"])
            key = normalize(name)
            if key not in nas_messages:
                protocol = "5GMM" if clause.startswith("8.2.") else "5GSM"
                nas_messages[key] = {
                    "display": name, "clause": clause, "protocol": protocol}
        for chunk in chunks:
            if chunk["spec"] != "24501":
                continue
            for run in _NAS_MSG_RUN.findall(_body(chunk)):
                key = normalize(run)
                if key in nas_messages:
                    nas_messages[key]["display"] = run
        for key, info in nas_messages.items():
            entities.append(EntityRef(
                type="message", spec="24501", name=info["display"],
                clause=info["clause"],
                id=f"message:24501:{info['clause']}:{info['display']}",
                protocol=info["protocol"], pattern_derived=True,
                display=info["display"]))
        # NGAP: the 9.4.3 ASN.1 elementary-procedure definitions name every
        # message; no text scan needed (prose spells them with spaces and
        # normalize() bridges query forms).
        body = self._joined_body(chunks, "38413", "9.4.3")
        for name in sorted(set(_NGAP_MSG_NAME.findall(body))):
            entities.append(EntityRef(
                type="message", spec="38413", name=name, clause="9.4.3",
                id=f"message:38413:9.4.3:{name}", protocol="NGAP",
                pattern_derived=True, display=name))
        # PFCP: 7.4.x.y headings are the message names.
        for (spec, clause), node in nodes.items():
            if spec == "29244" and re.match(r"^7\.4\.\d+\.\d+$", clause):
                entities.append(EntityRef(
                    type="message", spec=spec, name=node["heading"],
                    clause=clause, id=f"message:{spec}:{clause}:{node['heading']}",
                    protocol="PFCP", pattern_derived=False,
                    display=node["heading"]))
        # SBI: heading-derived service/operation names, plus body mentions
        # validated against that vocabulary (the exact name or its service
        # family up to the first "_" — "Nudm_SDM_Get" passes on the
        # "Nudm_UEAuthentication Service" heading). Unseen families
        # ("Npcf_…") never enter the vocabulary.
        sbi_headings: set = set()   # (spec, clause, name) from headings
        sbi_vocab: set = set()
        for (spec, clause), node in nodes.items():
            if spec not in _SBI_SPECS:
                continue
            for name in set(_SBI_NAME.findall(node["heading"])):
                sbi_headings.add((spec, clause, name))
                sbi_vocab.update((name, name.split("_", 1)[0]))
        for spec, clause, name in sorted(sbi_headings):
            entities.append(EntityRef(
                type="message", spec=spec, name=name, clause=clause,
                id=f"message:{spec}:{clause}:{name}", protocol="SBI",
                pattern_derived=False, display=name))
        seen_sbi = set(sbi_headings)
        for chunk in chunks:
            if chunk["spec"] not in _SBI_SPECS:
                continue
            for name in sorted(set(_SBI_NAME.findall(_body(chunk)))):
                key = (chunk["spec"], chunk["clause"], name)
                if key in seen_sbi:
                    continue  # this clause's own heading already named it
                seen_sbi.add(key)
                if name in sbi_vocab or name.split("_", 1)[0] in sbi_vocab:
                    entities.append(EntityRef(
                        type="message", spec=chunk["spec"], name=name,
                        clause=chunk["clause"],
                        id=f"message:{chunk['spec']}:{chunk['clause']}:{name}",
                        protocol="SBI", pattern_derived=True, display=name))
        # ProblemDetails never matches the N-name pattern; 29.500 j70
        # references it only (the type moved to TS 29.571), so a corpus
        # whose clause tree does carry the heading gets the entity for free.
        pd_clause = next((clause for (spec, clause), node in nodes.items()
                          if spec == "29500"
                          and node["heading"] == "ProblemDetails"), None)
        if pd_clause is not None:
            entities.append(EntityRef(
                type="message", spec="29500", name="ProblemDetails",
                clause=pd_clause,
                id=f"message:29500:{pd_clause}:ProblemDetails",
                protocol="SBI", pattern_derived=False,
                display="ProblemDetails"))

        # defined_in: cause -> the IE entity of its own table clause.
        ie_by_key = {(e.spec, e.clause): e for e in entities
                     if e.type == "ie"}
        for cause in (e for e in entities if e.type == "cause"):
            edges.add((cause.id, ie_by_key[(cause.spec, cause.clause)].id,
                       "defined_in", True))

        # co_mentioned: per chunk, cross-type pairs among {cause, message,
        # procedure}. Same-type pairs are never created (a cause table chunk
        # alone would otherwise link every cause to every cause). NGAP
        # causes are excluded (value-less names like "Unspecified" would
        # match arbitrary prose), as are one-word displays ("Reserved.").
        # SBI messages are excluded: their dialect has no cause/procedure
        # peers, so they never form co_mentioned edges (and the corpus-wide
        # display scan would pay for thousands of dead entities).
        messages = [e for e in entities
                    if e.type == "message" and e.protocol != "SBI"]
        causes = [e for e in entities
                  if e.type == "cause" and e.protocol != "NGAP"
                  and len(e.display.split()) >= 2]
        procedures = [e for e in entities if e.type == "procedure"]
        for chunk in chunks:
            text = _body(chunk).lower()
            present = {kind: [] for kind in ("cause", "message", "procedure")}
            present["cause"] = [c.id for c in causes
                                if c.display.lower() in text]
            present["message"] = [m.id for m in messages
                                  if m.display.lower() in text]
            clause = chunk["clause"]
            present["procedure"] = [p.id for p in procedures
                                    if clause.startswith(p.clause + ".")]
            for kind_a, kind_b in (("cause", "message"),
                                   ("cause", "procedure"),
                                   ("message", "procedure")):
                for id_a in present[kind_a]:
                    for id_b in present[kind_b]:
                        edges.add(tuple(sorted((id_a, id_b)))
                                  + ("co_mentioned", False))

        return {
            "corpus_sha256": corpus_sha,
            "entities": sorted(
                ({"type": e.type, "spec": e.spec, "name": e.name,
                  "clause": e.clause, "id": e.id, "protocol": e.protocol,
                  "pattern_derived": e.pattern_derived, "display": e.display,
                  "value": e.value, "group": e.group}
                 for e in entities),
                key=lambda d: d["id"]),
            "edges": sorted(
                ({"src": src, "dst": dst, "kind": kind, "exact": exact}
                 for src, dst, kind, exact in edges),
                key=lambda d: (d["src"], d["dst"], d["kind"])),
        }

    def _joined_body(self, chunks: list[dict], spec: str,
                     clause: str) -> str:
        """Bodies of all chunks of one clause, joined (continuation chunks
        split a table across several chunks)."""
        return "\n".join(_body(chunk) for chunk in chunks
                         if chunk["spec"] == spec
                         and chunk["clause"] == clause)

    def resolve(self, query: str) -> EntityRef | None:
        """Deterministic query -> entity, or None for a plain flat-hit answer.

        1) cause-number pattern ("cause #21", "cause=91", "what does 5GMM
           cause #111 mean"); bare values prefer the 5GMM table, then
           ascending spec/clause. A cause-number query with no matching
           cause resolves to nothing (falling through would let the name
           branch match the "Cause" IE on "cause 9999"). 2) longest
           normalized name key contained in the query (messages beat
           procedures beat IEs on a tie), so "CONTROL PLANE SERVICE
           REQUEST" outranks "SERVICE REQUEST" and "5GMM STATUS #91"
           resolves to the 5GMM status message.
        """
        self.ensure()
        match = _CAUSE_RE.search(query)
        if match:
            protocol = (match.group(1) or "").upper()
            value = int(match.group(2))
            candidates = [cause for cause in self._causes
                          if cause.value == value
                          and (not protocol or cause.protocol == protocol)]
            if candidates:
                candidates.sort(key=lambda cause: (
                    cause.clause != "9.11.3.2", cause.spec, cause.clause))
                return candidates[0]
            return None
        query_key = normalize(query)
        for key, ref in self._names:
            if key in query_key:
                return ref
        return None

    def entity_block(self, ref: EntityRef) -> list[str]:
        """The prepended context block for one resolved entity."""
        if ref.type == "cause":
            suffix = f" ({ref.group})" if ref.group else ""
            # NGAP names already carry the display ('NGAP cause "X"'); the
            # quoted display is only added when it adds information.
            display = "" if ref.display in ref.name else f' "{ref.display}"'
            lines = [f"entity {ref.name}{suffix}{display}"]
            ie = self._ie_by_key.get((ref.spec, ref.clause))
            if ie is not None:
                lines.append(
                    f"  defined_in: {ie.name} IE (clause {ref.clause})")
            return lines + self._co_mentioned_lines(ref, "message")
        if ref.type == "message":
            tag = "message, from text" if ref.pattern_derived else "message"
            return ([f"entity {ref.name} ({tag})"]
                    + self._co_mentioned_lines(ref, "cause"))
        if ref.type == "ie":
            return ([f"entity {ref.name} (IE)"]
                    + self._co_mentioned_lines(ref, "message"))
        if ref.type == "procedure":
            return [f"entity {ref.name} (procedure)"]
        return [f"entity {ref.clause} {ref.name} (clause)"]

    def _co_mentioned_lines(self, ref: EntityRef,
                            neighbor_type: str) -> list[str]:
        neighbors = sorted((n for n in self._adjacency.get(ref.id, ())
                            if n.type == neighbor_type),
                           key=lambda n: n.name)
        if not neighbors:
            return []
        more = ""
        if len(neighbors) > MESSAGE_CAP:
            more = f" … and {len(neighbors) - MESSAGE_CAP} more"
        names = [n.name for n in neighbors[:MESSAGE_CAP]]
        lines = _wrap("co-mentioned: " + ", ".join(names) + more)
        return [f"  {lines[0]}"] + lines[1:]


def _wrap(text: str) -> list[str]:
    if len(text) <= WRAP:
        return [text]
    words, lines, current = text.split(" "), [], ""
    for word in words:
        if current and len(current) + 1 + len(word) > WRAP:
            lines.append(current)
            current = " " * CONTINUATION + word
        else:
            current = f"{current} {word}" if current else word
    lines.append(current)
    return lines
