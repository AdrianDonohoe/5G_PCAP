# Spec graph: typed entities and hybrid retrieval over the 3GPP corpus

The `query_3gpp_spec` tool's flat embedding index (ADR-0002) answers prose
questions well, but the agent's exact questions ("what does 5GMM cause #111
mean", "5GMM STATUS #91") deserve the exact answer: the cause row, the IE
that defines it, the messages it co-occurs with. The six sandbox failure
scenarios (ADR-0002's fixture generation) all hinge on such entities, and
ranked prose chunks are a weaker answer than the entity itself. This ADR
adds a **spec graph** — a typed entity graph extracted deterministically at
corpus-build time, cached beside the embedding index, and consulted only to
*enrich* `query_3gpp_spec`'s observation, never to replace it.

## Status

accepted

## Considered Options

**Graph extraction** — a Microsoft-GraphRAG-style LLM extraction pass
(entity/relationship summarization) vs. deterministic rules. Rejected the
LLM pass: it violates ADR-0002 (the corpus build must stay one-time and
offline), adds a per-corpus-rebuild model cost, and its output is not
reproducible across runs. Chose deterministic per-spec-family rules
(NAS/NGAP/PFCP clause dialects): cause tables parse to Cause entities with
values, IE/procedure clauses parse by structure, and message names parse
from the 9.7/9.4.3 vocabulary tables and 7.4.x.y headings. The corpus is
pinned 19.x, so the rules are verified once against the committed chunks
and stay valid until a corpus bump.

**Where entity knowledge lives** — query-time regex over raw chunks vs.
hand-maintained entity lists vs. a build-time cached graph. Rejected the
first (re-derives the same structure on every call, and can't express
edges), rejected the second (drifts from the corpus the moment the corpus
bumps). Chose the cached graph: `build()` runs once over chunks.jsonl and
writes `corpus/cache/specgraph-{sha16}.json`, keyed on the corpus sha256 —
the same invalidation as the embedding index, so both artifacts rebuild
exactly when the corpus changes.

**Entity typing honesty** — Clause/Procedure/IE/Cause entities derive from
clause structure and table rows and are exact. Message entities are
*pattern-derived* from ALL-CAPS/CamelCase name runs in text, validated
against an exact per-spec vocabulary (the 9.7 message-type table and the
9.4.3 ASN.1 definitions); each carries `pattern_derived: true`, and the
observation renders them as "message, from text". PFCP messages are
heading-derived and carry `pattern_derived: false`. Rejected marking all
messages exact: the vocabulary-validation step is what keeps "PDU SESSION
INACTIVE", "RAND", and IE names out of the entity set, and the flag keeps
the provenance visible to the agent.

**Co-occurrence edges** — include or exclude within-chunk co-mention
inference. Chose include: a chunk pairing "Synch failure" with
AUTHENTICATION REJECT *is* signal (it's the Annex A cause-usage guidance
the agent is trying to recall), and dropping it loses the one edge type
that connects causes to messages. The edges are cross-type only (a cause
table chunk would otherwise link every cause to every cause), NGAP causes
are excluded (value-less names like "Unspecified" match arbitrary prose),
and the observation always labels them "co-mentioned" — exact edges
(`contains`, `defined_in`) render unqualified, inference never does.

**Interface** — new tool vs. enrich in place. Chose enrich in place:
`query_3gpp_spec` gains an opt-in `graph` kwarg, and its observation
template gains one prepended block when a query resolves to an entity.
`SpecIndex.search()` and every existing template stay byte-identical when
no entity resolves; the graph defaults in only on the production path
(`index is None`), and any graph failure degrades to plain hits behind the
same try/except that already guards the index. Entity resolution is exact
per query form: a cause-number pattern (`"cause #21"`, `"cause=91"`,
`"what does 5GMM cause #111 mean"`) resolves against the parsed tables
(the 5GMM table wins bare-value ties, since 67 and 111 exist in both
tables), and otherwise the longest normalized name key contained in the
query wins (`normalize()` bridges the decoder form "5GMMStatus" and the
spec form "5GMM status"; "CONTROL PLANE SERVICE REQUEST" outranks "SERVICE
REQUEST"). NGAP causes are not number-resolvable — the ENUMERATED table
carries no values — which is documented, not hidden: an NGAP cause query
falls through to ranked prose.

**Output** — the approved observation shape for a resolved entity:

```
3GPP spec retrieval for "cause #21" (2 hit(s); entity: 5GMM cause #21):
entity 5GMM cause #21 "Synch failure"
  defined_in: 5GMM cause IE (clause 9.11.3.2)
  co-mentioned: AUTHENTICATION FAILURE, AUTHENTICATION REJECT, AUTHENTICATION
                REQUEST, AUTHENTICATION RESPONSE, REGISTRATION REJECT,
                REGISTRATION REQUEST, SECURITY MODE COMMAND, SECURITY MODE
                REJECT … and 1 more
[1] score=0.685
…
```

Co-mentioned names wrap at 80 columns under "co-mentioned: ", cap at 8 with
"… and N more", and every hit/empty-hit/miss combination was reviewed
before the templates were extended.

## Consequences

- The pytest suite stays offline and free (ADR-0002): extraction rules are
  pinned against hand-written fixture corpora per dialect, and the seven
  incident fixture queries (`cause #21`, `5GMM cause #111`, `5GMM cause #7`,
  `5GMM STATUS #91`, `5GSM cause 67`, `5GMM cause #90`, `5GMM cause #91`)
  are pinned against one session-scoped build of the committed corpus in
  tmp (~3 s).
- `evals/` inherits the enrichment unchanged — it calls
  `query_3gpp_spec` through the same search loop, so eval runs see the
  entity context for free, and no eval fixture changes are required.
- The graph cache lives beside the embedding index under
  `corpus/cache/` (already gitignored); both rebuild exactly when
  chunks.jsonl changes. Rule changes to extraction require deleting the
  cache file — it is keyed on corpus bytes, not code.
- The typed graph (entities + edges as JSON) is deliberately reusable
  outside this tool: the planned post-incident report writer can traverse
  the same `defined_in`/`co_mentioned` structure without re-deriving it.
- `query_3gpp_spec`'s degradation contract is unchanged: index failure
  still returns the authoritative "3GPP spec index unavailable" string,
  and graph failure silently degrades to plain hits.
