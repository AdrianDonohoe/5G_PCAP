"""KPI tests on a deterministic synthetic capture."""

import pytest
from pathlib import Path

from fivegcap.capture import read_capture
from fivegcap.flow import build_flows
from fivegcap.kpi import compute
from fivegcap.ngap import decode

from synth import build_synthetic

SYNTH = Path(__file__).parent / "fixtures" / "synthetic.pcap"


def analyze():
    raw = read_capture(str(SYNTH))
    msgs = [decode(m.ts, m.assoc, m.stream, m.data) for m in raw]
    flows, unassociated = build_flows(msgs)
    return flows, compute(flows)


def test_kpis_on_synthetic_capture():
    build_synthetic(str(SYNTH))
    flows, kpi = analyze()
    assert len(flows) == 1
    f = flows[0]
    assert not f.partial
    kinds = [p.kind for p in f.procedures]
    assert kinds == ["registration", "pdu_session_est", "registration"]
    # registration #1: 100 ms, registration #2: 30 ms (pcap ts resolution rounding)
    assert kpi.attach_times_ms[0] == pytest.approx(100.0)
    assert kpi.attach_times_ms[1] == pytest.approx(30.0)
    assert kpi.attach_time_ms == pytest.approx(65.0)
    # pdu session establishment: 50 ms
    assert kpi.pdu_session_times_ms == pytest.approx([50.0])
    assert kpi.pdu_session_time_ms == pytest.approx(50.0)
    # 2 accepts, 1 reject
    assert (kpi.successes, kpi.failures) == (2, 1)
    assert abs(kpi.success_rate - 2 / 3) < 1e-9


def test_retransmission_does_not_duplicate_messages():
    build_synthetic(str(SYNTH))
    flows, _ = analyze()
    # 7 packets written, one is a retransmission -> 6 unique messages
    assert len(flows[0].messages) == 6
