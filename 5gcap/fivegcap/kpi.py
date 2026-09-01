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
    only. Each flow's joined legs are grouped into per-session triples by
    their procedure anchors: the sm-contexts create's pduSessionId, the N4
    establishment response's Created-PDR tunnel against the SetupRequest
    item's UPF endpoint, and the SetupResponse item's pDUSessionID. Each
    KPI needs its legs present exactly once per session — a session
    missing or ambiguous on a leg is excluded from every KPI that needs
    it, nothing is ever estimated. The SBI leg is the create that reached
    the SMF running the session (the establishment response's dst_ip);
    without an N4 anchor for the session it is matched by pduSessionId
    alone. Flows with no session anchors anywhere degrade to the per-flow
    exactly-once discipline."""
    sbi_to_n4, n4_to_n2, sbi_to_n2 = [], [], []
    for f in flows:
        setup_reqs = [ng for ng, _ in f.messages
                      if ng.name == "PDUSessionResourceSetupRequest"]
        setup_rsps = [ng for ng, _ in f.messages
                      if ng.name == "PDUSessionResourceSetupResponse"]
        est_rsps = [n4_msgs[i] for i in corr.flow_n4_refs.get(f.flow_id, [])
                    if n4_msgs[i].name == "PFCP Session Establishment Response"]
        creates = [sbi_msgs[i] for i in corr.flow_sbi_refs.get(f.flow_id, [])
                   if (sbi_msgs[i].direction == "request"
                       and sbi_msgs[i].method == "POST"
                       and sbi_msgs[i].path == "/nsmf-pdusession/v1/sm-contexts")]
        # Per-session anchors: the SetupRequest items' UPF-endpoint
        # tunnels and the SetupResponse items' timestamps, keyed by
        # pDUSessionID, plus the creates' pduSessionId.
        req_tunnels: dict[int, set] = {}
        rsp_ts: dict[int, list[float]] = {}
        for ng in setup_reqs:
            for sid, tunnels in ng.req_session_tunnels.items():
                req_tunnels.setdefault(sid, set()).update(tunnels)
        for ng in setup_rsps:
            for sid, count in ng.rsp_session_counts.items():
                rsp_ts.setdefault(sid, []).extend([ng.ts] * count)
        session_ids = set(req_tunnels) | set(rsp_ts) | {
            c.pdu_session_id for c in creates if c.pdu_session_id is not None}
        if not session_ids:
            # No per-session anchors: the per-flow exactly-once discipline.
            smf_ip = est_rsps[0].dst_ip if len(est_rsps) == 1 else None
            cs = [c for c in creates if smf_ip is None or c.dst_ip == smf_ip]
            create = cs[0] if len(cs) == 1 else None
            est = est_rsps[0] if len(est_rsps) == 1 else None
            setup = setup_rsps[0] if len(setup_rsps) == 1 else None
            if create is not None and est is not None:
                sbi_to_n4.append((est.ts - create.ts) * 1000.0)
            if est is not None and setup is not None:
                n4_to_n2.append((setup.ts - est.ts) * 1000.0)
            if create is not None and setup is not None:
                sbi_to_n2.append((setup.ts - create.ts) * 1000.0)
            continue
        # The N4 leg anchors to its session via the Created-PDR tunnel; an
        # establishment response matching two sessions anchors neither.
        est_by_session: dict[int, list] = {}
        for e in est_rsps:
            hits = {sid for sid, tunnels in req_tunnels.items()
                    if set(e.f_teids) & tunnels}
            if len(hits) == 1:
                est_by_session.setdefault(hits.pop(), []).append(e)
        for sid in sorted(session_ids):
            est_s = est_by_session.get(sid, [])
            est = est_s[0] if len(est_s) == 1 else None
            if est is not None:
                # The SBI leg is the create that reached the SMF running
                # the session (the establishment response's dst).
                cs = [c for c in creates
                      if c.pdu_session_id == sid and c.dst_ip == est.dst_ip]
            else:
                # No N4 anchor for the session: the create leg is matched
                # by pduSessionId alone — two creates stay ambiguous.
                cs = [c for c in creates if c.pdu_session_id == sid]
            create = cs[0] if len(cs) == 1 else None
            setup_s = rsp_ts.get(sid, [])
            setup_ts = setup_s[0] if len(setup_s) == 1 else None
            if create is not None and est is not None:
                sbi_to_n4.append((est.ts - create.ts) * 1000.0)
            if est is not None and setup_ts is not None:
                n4_to_n2.append((setup_ts - est.ts) * 1000.0)
            if create is not None and setup_ts is not None:
                sbi_to_n2.append((setup_ts - create.ts) * 1000.0)
    return {"sbi_to_n4_ms": _mean(sbi_to_n4),
            "n4_to_n2_ms": _mean(n4_to_n2),
            "sbi_to_n2_ms": _mean(sbi_to_n2)}
