# Cross-plane correlation joins on strict key equality, never heuristics

Spec #6 links the three plane views (N2, SBI, N4) of a capture set so one UE's signaling can be followed end to end. The sandbox proves every natural join key (GTP tunnel endpoints, plaintext SUPI) co-occurs on the wire with exact matches, and it is tempting to add a heuristic matcher — timing windows, IP proximity, request counts — to link the messages exact keys leave unlinked. We chose exact equality only: a link exists or it doesn't, never a guess.

## Status

accepted

## Considered Options

- **Heuristic matching** (timing, IP adjacency, cardinality): links more messages, but silently — a wrong link looks identical to a right one to everything downstream, and a triage diagnosis citing another UE's session as evidence is worse than no link at all. Rejected.
- **Strict key equality (chosen)**: a join happens only where the same natural key appears on the wire in both planes, compared exactly. Messages without a matching key stay unlinked, and the export says so.

## Consequences

- **A null-scheme SUCI counts as plaintext SUPI.** A SUCI whose protection scheme is the null scheme (ProtSchemeID 0) wraps the SUPI in plaintext BCD (PLMN + MSIN), so extraction normalizes it to the plaintext SUPI and it joins like any other plaintext identity. A protected SUCI (ECIES) is unreadable without the UDM's keys and never joins.
- **The N4 User-ID IMSI is extracted as evidence, deliberately not a join key.** The PFCP session establishment's User ID IE carries the IMSI, which looks like the obvious N2↔N4 key — but the N2 side never declares a plaintext IMSI (NAS identities are SUCI and 5G-GUTI), so the key exists on one side only and would inherit null-scheme-only coverage. The wire supplies the key that exists in both planes: the GTP tunnel endpoint.
- **Create-FAR placeholders are never keys.** The session establishment's Create FAR carries a placeholder FAR ID with a dummy TEID — the real endpoint arrives later, in the modification's Update FAR Outer Header Creation — so counting it would manufacture false links. Only the Created PDR F-TEID and the Update FAR declare tunnel endpoints.
- **N4 procedures inherit their request's flow if linked, else their response's.** The session-establishment join key — the Created PDR F-TEID, matched against the SetupRequest's UPF endpoint — lives on the response; the request's Create PDR/FAR carry no key (a choose-id F-TEID and placeholder TEIDs, never keys), so an establishment procedure can only carry a flow via its response. This response-side link is also what `sbi_to_n4_ms` anchors on: the KPI pairs each flow's establishment responses with its sm-contexts creates. SBI procedures keep request-only inheritance — an SBI response carries no identity of its own, and inherits through its request's (conn, stream) pairing.
- **An ambiguous key yields no link.** A key claimed by more than one Flow (a SUPI seen in two registrations, a reused TEID) matches no Flow: picking either would be a guess. Likewise a message whose keys span two Flows links none — one message cannot belong to two UEs — and a message the lenient decoder refused (unparsed) carries no keys to compare, so it never joins.
