"""Self-generated Open5GS+UERANSIM captures from sandbox/capture.sh.

Unlike the other fixtures, these are regenerated locally on demand (see
docs/adr/0002-open5gs-ueransim-sandbox.md), so assertions check structure and
outcomes rather than exact latencies, which vary between runs.
"""

from pathlib import Path

from fivegcap.capture import read_capture, read_pfcp_capture
from fivegcap.flow import build_flows
from fivegcap.kpi import compute
from fivegcap.ngap import decode as ngap_decode
from fivegcap.pfcp import decode as pfcp_decode, pair_procedures

N2_FIXTURE = Path(__file__).parent / "fixtures" / "sandbox_n2.pcap"
N4_FIXTURE = Path(__file__).parent / "fixtures" / "sandbox_n4.pcap"


def test_n2_decodes_and_computes_kpis():
    raw = read_capture(str(N2_FIXTURE))
    assert raw, "no NGAP messages decoded from sandbox_n2.pcap"
    msgs = [ngap_decode(m.ts, m.assoc, m.stream, m.data) for m in raw]
    flows, unassociated = build_flows(msgs)

    assert len(flows) == 3
    for f in flows:
        assert not f.partial, f"flow {f.flow_id} missing its start message"
        kinds = [p.kind for p in f.procedures]
        assert kinds == ["registration", "pdu_session_est"]
        assert all(p.outcome == "accept" for p in f.procedures)

    kpi = compute(flows)
    assert kpi.success_rate == 1.0
    assert (kpi.successes, kpi.failures) == (6, 0)
    assert len(kpi.attach_times_ms) == 3
    assert len(kpi.pdu_session_times_ms) == 3
    assert all(ms > 0 for ms in kpi.attach_times_ms + kpi.pdu_session_times_ms)


def test_n4_decodes_and_pairs_procedures():
    raw = read_pfcp_capture(str(N4_FIXTURE))
    assert raw, "no PFCP messages decoded from sandbox_n4.pcap"
    msgs = [pfcp_decode(m.ts, m.data) for m in raw]

    assert all(m.unparsed is None for m in msgs)

    procedures, unpaired = pair_procedures(msgs)
    assert unpaired == []
    session_est = [p for p in procedures if p.kind == "session_establishment"]
    assert len(session_est) == 3
    assert all(p.outcome == "accept" for p in procedures if p.kind != "heartbeat")
