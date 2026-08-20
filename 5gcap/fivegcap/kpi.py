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


def _mean(times: list[float]) -> float | None:
    return sum(times) / len(times) if times else None


def cross_plane_kpis(flows: list[Flow], corr, sbi_msgs, n4_msgs) -> dict:
    """The three cross-plane PDU-session latency means (ms), complete flows
    only. Each KPI needs its legs present exactly once: the SBI leg is the
    flow's sm-contexts create at the SMF that ran the session (its dst_ip
    equals the joined N4 establishment response's dst_ip; without that
    response the flow's creates must be unambiguous), the N4 leg is that
    response, the N2 leg the flow's PDU-session SetupResponse. A flow
    missing a leg is excluded from every KPI that needs it; nothing is
    ever estimated."""
    sbi_to_n4, n4_to_n2, sbi_to_n2 = [], [], []
    for f in flows:
        setup_rsps = [ng for ng, _ in f.messages
                      if ng.name == "PDUSessionResourceSetupResponse"]
        est_rsps = [n4_msgs[i] for i in corr.flow_n4_refs.get(f.flow_id, [])
                    if n4_msgs[i].name == "PFCP Session Establishment Response"]
        smf_ip = est_rsps[0].dst_ip if len(est_rsps) == 1 else None
        creates = [sbi_msgs[i] for i in corr.flow_sbi_refs.get(f.flow_id, [])
                   if (sbi_msgs[i].direction == "request"
                       and sbi_msgs[i].method == "POST"
                       and sbi_msgs[i].path == "/nsmf-pdusession/v1/sm-contexts"
                       and (smf_ip is None or sbi_msgs[i].dst_ip == smf_ip))]
        create = creates[0] if len(creates) == 1 else None
        est = est_rsps[0] if len(est_rsps) == 1 else None
        setup = setup_rsps[0] if len(setup_rsps) == 1 else None
        if create is not None and est is not None:
            sbi_to_n4.append((est.ts - create.ts) * 1000.0)
        if est is not None and setup is not None:
            n4_to_n2.append((setup.ts - est.ts) * 1000.0)
        if create is not None and setup is not None:
            sbi_to_n2.append((setup.ts - create.ts) * 1000.0)
    return {"sbi_to_n4_ms": _mean(sbi_to_n4),
            "n4_to_n2_ms": _mean(n4_to_n2),
            "sbi_to_n2_ms": _mean(sbi_to_n2)}
