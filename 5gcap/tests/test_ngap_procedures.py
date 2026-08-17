"""NGAP-milestone procedure pairing on a real successful-attach capture."""

from pathlib import Path

import pytest

from fivegcap.capture import read_capture
from fivegcap.flow import build_flows
from fivegcap.kpi import compute
from fivegcap.ngap import decode

FIXTURE = Path(__file__).parent / "fixtures" / "scenario1.pcap"


def analyze():
    raw = read_capture(str(FIXTURE))
    msgs = [decode(m.ts, m.assoc, m.stream, m.data) for m in raw]
    flows, unassociated = build_flows(msgs)
    return flows, compute(flows)


def test_ngap_fallback_procedures():
    flows, kpi = analyze()
    f = next(f for f in flows if not f.partial)
    kinds = [p.kind for p in f.procedures]
    assert kinds == ["registration", "pdu_session_est"]
    reg = f.procedures[0]
    # The registration terminal is integrity-protected but plaintext, so the
    # NAS pair is the more precise measurement (same timestamps as the NGAP
    # carriers that hold it).
    assert (reg.start_msg, reg.end_msg, reg.outcome) == (
        "5GMMRegistrationRequest",
        "5GMMRegistrationAccept",
        "accept",
    )
    pdu = f.procedures[1]
    # The PDU terminal stays invisible (ciphering unknown in this capture);
    # the NGAP carriers pair instead.
    assert (pdu.start_msg, pdu.end_msg, pdu.outcome) == (
        "PDUSessionResourceSetupRequest",
        "PDUSessionResourceSetupResponse",
        "accept",
    )
    # ~12 ms attach; ~13.4 ms pdu session (pcap ts resolution)
    assert kpi.attach_time_ms == pytest.approx(12.0, abs=0.1)
    assert kpi.pdu_session_time_ms == pytest.approx(13.43, abs=0.1)
    assert kpi.success_rate == 1.0
    assert (kpi.successes, kpi.failures) == (2, 0)


def test_open_flow_contributes_no_latency():
    flows, kpi = analyze()
    # flow 2 (service-request cycle) starts with InitialUEMessage but never
    # reaches an InitialContextSetup — no procedure, no KPI contribution.
    f2 = next(f for f in flows if len(f.messages) == 1)
    assert f2.procedures == []
    assert len(kpi.attach_times_ms) == 1  # only the complete flow contributes
