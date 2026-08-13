"""Golden decode tests against the real modem-test capture."""

from pathlib import Path

import pytest

from fivegcap.capture import read_capture
from fivegcap.flow import build_flows
from fivegcap.kpi import compute
from fivegcap.ngap import decode

FIXTURE = Path(__file__).parent / "fixtures" / "modem_testrun.pcap"


def analyze():
    raw = read_capture(str(FIXTURE))
    msgs = [decode(m.ts, m.assoc, m.stream, m.data) for m in raw]
    flows, unassociated = build_flows(msgs)
    return raw, msgs, flows, unassociated


def test_retransmissions_dropped():
    raw, *_ = analyze()
    # 369 raw NGAP chunks, 62 of them retransmissions
    assert len(raw) == 307


def test_decode_never_fatal():
    _, msgs, *_ = analyze()
    # every message decodes; lenient failures only appear as unparsed notes
    assert all(m.name is not None for m in msgs)


def test_flows_and_unassociated():
    _, _, flows, unassociated = analyze()
    assert len(flows) == 36
    # NGSetup and friends are network-level, not per-UE flows
    names = {m.name for m in unassociated}
    assert {"NGSetupRequest", "NGSetupResponse"} <= names
    assert all(m.name == "InitialUEMessage" for f in flows for m, _ in f.messages[:1])


def test_nas_names_seen():
    _, _, flows, _ = analyze()
    nas_names = {nas.name for f in flows for _, nas in f.messages if nas}
    assert "5GMMRegistrationRequest" in nas_names
    assert "5GMMAuthenticationRequest" in nas_names
    # protected NAS is surfaced, not dropped
    protected = sum(1 for f in flows for _, nas in f.messages if nas and nas.protected)
    assert protected > 0


def test_ngsetup_decodes_real_values():
    _, _, _, unassociated = analyze()
    setup = next(m for m in unassociated if m.name == "NGSetupRequest")
    assert setup.ies["GlobalRANNodeID"][0] == "globalGNB-ID"
    assert setup.ies["RANNodeName"] == "srsgnb01"


def test_attach_pairs_with_current_cycle_not_stale():
    # Flow 1's first registration cycle dies with SecurityModeReject + release
    # before any context setup; the attach KPI must pair the SECOND cycle's
    # InitialUEMessage (225.196s) with its InitialContextSetupRequest (225.527s),
    # not the stale first cycle (200.239s) — which would read ~25 s.
    _, _, flows, _ = analyze()
    kpi = compute(flows)
    assert kpi.attach_time_ms is not None
    assert kpi.attach_time_ms == pytest.approx(331.0, abs=1.0)
    assert len(kpi.attach_times_ms) == 1
