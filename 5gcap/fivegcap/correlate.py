"""Cross-plane correlation: strict key equality joins, never heuristics.

N2↔SBI joins on the SUPI: a null-scheme SUCI is plaintext (normalized at
extraction), a protected one never joins. A key present in more than one
flow is ambiguous and yields no link; a refused message never joins. The
export carries the links; triage only consumes them. (N2↔N4 tunnel joins
follow in #9.)
"""

from dataclasses import dataclass, field

from .flow import Flow
from .sbi import SbiMsg


@dataclass
class Correlation:
    sbi_flow: dict = field(default_factory=dict)       # sbi message index -> flow_id | None
    flow_sbi_refs: dict = field(default_factory=dict)  # flow_id -> sorted sbi indexes


def _flow_supis(flows: list[Flow]) -> dict[str, set[int]]:
    """supi -> the flow ids whose NAS messages declared it."""
    claims: dict[str, set[int]] = {}
    for f in flows:
        for _, nas in f.messages:
            if nas is not None and nas.supi:
                claims.setdefault(nas.supi, set()).add(f.flow_id)
    return claims


def _join_sbi(corr: Correlation, msgs: list[SbiMsg],
              claims: dict[str, set[int]]) -> None:
    # A SUPI claimed by more than one flow is ambiguous: no links for it.
    unambiguous = {s: next(iter(fs)) for s, fs in claims.items() if len(fs) == 1}
    # Requests join by their declared SUPI; a response inherits its
    # request's flow via the exact (conn, stream) pairing the procedures
    # use. A refused (unparsed) message never joins.
    req_flow: dict[tuple, int] = {}
    for i, m in enumerate(msgs):
        corr.sbi_flow[i] = None
        if (m.direction == "request" and m.unparsed is None
                and m.conn is not None and m.supi in unambiguous):
            fid = unambiguous[m.supi]
            corr.sbi_flow[i] = fid
            corr.flow_sbi_refs.setdefault(fid, []).append(i)
            req_flow[(m.conn, m.stream_id)] = fid
    for i, m in enumerate(msgs):
        if m.direction == "response" and m.conn is not None:
            fid = req_flow.get((m.conn, m.stream_id))
            if fid is not None:
                corr.sbi_flow[i] = fid
                corr.flow_sbi_refs.setdefault(fid, []).append(i)
    for refs in corr.flow_sbi_refs.values():
        refs.sort()


def correlate(flows: list[Flow],
              sbi_msgs: list[SbiMsg] | None = None) -> Correlation:
    """Join the planes by their natural keys. A link exists or it doesn't."""
    corr = Correlation()
    if sbi_msgs:
        _join_sbi(corr, sbi_msgs, _flow_supis(flows))
    return corr
