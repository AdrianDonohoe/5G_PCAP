"""v1 KPIs: attach time, PDU session establishment time, procedure success rate.

Latency KPIs use complete procedures only; success rate covers every procedure
with a terminal outcome (CONTEXT.md: Partial Flows are excluded from latency).
"""

from dataclasses import dataclass, field

from .flow import Flow, Procedure


@dataclass
class KpiResult:
    attach_times_ms: list = field(default_factory=list)      # per completed registration
    pdu_session_times_ms: list = field(default_factory=list)  # per completed est.
    successes: int = 0
    failures: int = 0

    @property
    def attach_time_ms(self) -> float | None:
        return sum(self.attach_times_ms) / len(self.attach_times_ms) if self.attach_times_ms else None

    @property
    def pdu_session_time_ms(self) -> float | None:
        return (
            sum(self.pdu_session_times_ms) / len(self.pdu_session_times_ms)
            if self.pdu_session_times_ms
            else None
        )

    @property
    def success_rate(self) -> float | None:
        total = self.successes + self.failures
        return self.successes / total if total else None


def compute(flows: list[Flow]) -> KpiResult:
    r = KpiResult()
    for f in flows:
        if f.partial:
            continue  # latency KPIs: complete flows only
        for p in f.procedures:
            ms = (p.end_ts - p.start_ts) * 1000.0
            if p.kind == "registration":
                r.attach_times_ms.append(ms)
            else:
                r.pdu_session_times_ms.append(ms)
    # Success rate over all observed terminal outcomes, partial flows included.
    for f in flows:
        for p in f.procedures:
            if p.outcome == "accept":
                r.successes += 1
            elif p.outcome == "reject":
                r.failures += 1
    return r
