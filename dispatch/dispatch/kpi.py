"""The KPI specialist agent: 5gcap as a subprocess, the Golden-baseline
comparator, and the Alarm event it synthesizes.

Three degradation rules over the computed KPIs and the export's message
sections: procedure success rate below golden, any latency KPI above twice
golden, and any cause-bearing reject message (a NAS Reject carrying
nas_cause, PFCP cause codes other than "Request accepted", SBI status >=
400). The comparator is pure; the subprocess is a stub seam (runner
injected in tests). Groq-free by construction."""

import hashlib
import json
import re
import shlex
import subprocess
import tempfile
from pathlib import Path

GOLDEN_PATH = Path(__file__).resolve().parents[2] / "dispatch" / "baseline" / "golden_kpis.json"

LATENCY_KEYS = ("attach_time_ms", "pdu_session_time_ms", "sbi_to_n4_ms",
                "n4_to_n2_ms", "sbi_to_n2_ms")

_CITATION_RE = re.compile(r"kpi\.([A-Za-z0-9_]+)=(.*)")


def load_golden() -> dict:
    """The committed Golden baseline (byte-stable; never hand-edited)."""
    return json.loads(GOLDEN_PATH.read_text())


def deviations(kpis: dict, golden: dict, flows=None, n4=None, sbi=None) -> list[dict]:
    """Pure comparator: one deviation dict per degradation found. Cause
    deviations carry the procedure KPI the reject degrades, so every detail
    names a deviating KPI."""
    devs = []
    cause_kpi = ("procedure_failures" if "procedure_failures" in kpis
                 else "procedure_success_rate")

    rate = kpis.get("procedure_success_rate")
    golden_rate = golden.get("procedure_success_rate")
    if rate is not None and golden_rate is not None and rate < golden_rate:
        devs.append({"rule": "success_rate", "kpi": "procedure_success_rate",
                     "detail": f"procedure_success_rate {rate} below golden "
                               f"{golden_rate}"})

    for name in LATENCY_KEYS:
        value = kpis.get(name)
        gold = golden.get(name)
        if value is not None and gold is not None and value > 2 * gold:
            devs.append({"rule": "latency", "kpi": name,
                         "detail": f"{name} {value} above twice golden {gold}"})

    for flow in flows or []:
        for message in flow.get("messages", []):
            cause = message.get("nas_cause")
            # Cause IEs also ride on non-rejects (AuthenticationFailure,
            # 5GMMStatus) — the rule is reject messages only. 5GSM rejects
            # arrive inside NAS transports, so the inner name wins.
            name = message.get("nas_inner") or message.get("nas") or ""
            if cause is None or "Reject" not in name:
                continue
            detail = f"reject message: {name} nas_cause {cause['code']}"
            if cause.get("name"):
                detail += f" ({cause['name']})"
            devs.append({
                "rule": "cause", "kpi": cause_kpi,
                "detail": detail + f" — kpi.{cause_kpi}={kpis[cause_kpi]}",
                "cause": str(cause["code"]), "flow_id": flow.get("flow_id"),
                "ts": message["ts"],
            })

    for message in (n4 or {}).get("messages", []):
        cause = message.get("cause_code")
        if cause is not None and cause != 1:  # 1 = "Request accepted"
            devs.append({
                "rule": "cause", "kpi": cause_kpi,
                "detail": f"reject message: "
                          f"{message.get('name') or 'PFCP'} cause_code {cause}"
                          f" — kpi.{cause_kpi}={kpis[cause_kpi]}",
                "cause": str(cause), "flow_id": message.get("flow_id"),
                "ts": message["ts"],
            })

    for message in (sbi or {}).get("messages", []):
        status = message.get("status")
        if status is not None and status >= 400:
            detail = f"reject message: {message.get('name') or 'SBI'} " \
                     f"status {status}"
            if message.get("problem_title"):
                detail += f" ({message['problem_title']})"
            devs.append({
                "rule": "cause", "kpi": cause_kpi,
                "detail": detail + f" — kpi.{cause_kpi}={kpis[cause_kpi]}",
                "cause": str(status), "flow_id": message.get("flow_id"),
                "ts": message["ts"],
            })

    return devs


def capture_window(export: dict) -> tuple[float, float]:
    """(first, last) message timestamp across all three planes."""
    timestamps = [m["ts"] for f in export.get("flows", [])
                  for m in f.get("messages", [])]
    timestamps += [m["ts"] for m in export.get("n4", {}).get("messages", [])]
    timestamps += [m["ts"] for m in export.get("sbi", {}).get("messages", [])]
    if not timestamps:
        raise ValueError("export has no message timestamps")
    return min(timestamps), max(timestamps)


def alarm_event(deviations: list[dict], kpis: dict, captures: dict,
                incident_id: str, detected_at: float,
                window: tuple[float, float]) -> dict | None:
    """The Alarm event (source: kpi) naming the deviating KPIs, or None."""
    if not deviations:
        return None
    return {
        "incident_id": incident_id,
        "detected_at": detected_at,
        "source": "kpi",
        "procedure": None,
        "time_window": {"start": window[0], "end": window[1]},
        "description": "KPI degradation: "
                       + "; ".join(d["detail"] for d in deviations),
        "kpi": kpis,
        "captures": captures,
    }


def kpi_evidence(deviations: list[dict], kpis: dict,
                 detected_at: float) -> list[dict]:
    """Evidence items whose citations name computed KPI names and values —
    grounded by construction, verified by passes_grounding. Every deviation
    carries its own kpi, so the citation is built one way."""
    return [{
        "source": "kpi",
        "kind": "reject message" if dev["rule"] == "cause" else "KPI deviation",
        "ts": dev.get("ts", detected_at),
        "entry": dev["detail"],
        "cause": dev.get("cause"),
        "endpoints": None,
        "keys": ({"flow_id": dev["flow_id"]}
                 if dev.get("flow_id") is not None else {}),
        "citation": f"kpi.{dev['kpi']}={kpis[dev['kpi']]}",
    } for dev in deviations]


def passes_grounding(item: dict, kpis: dict) -> bool:
    """The grounding check: a citation must name a computed KPI and match
    its value exactly."""
    match = _CITATION_RE.fullmatch(item.get("citation", ""))
    if not match:
        return False
    name, raw = match.group(1), match.group(2)
    if name not in kpis:
        return False
    try:
        return float(raw) == kpis[name]
    except ValueError:
        return False


def run_analyze(captures: dict, runner=None) -> dict:
    """Run `5gcap analyze` as a subprocess and parse the merged export.
    ``runner`` is the stub seam; the real run goes through subprocess.run."""
    n2 = captures.get("n2")
    if not n2:
        raise ValueError("detect-kpi requires an N2 capture")
    repo = Path(__file__).resolve().parents[2]
    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tmp.close()
    try:
        command = (f"uv run --project {repo}/5gcap 5gcap analyze "
                   f"{shlex.quote(str(n2))} --json {shlex.quote(tmp.name)}")
        if captures.get("sbi"):
            command += f" --sbi {shlex.quote(str(captures['sbi']))}"
        if captures.get("n4"):
            command += f" --n4 {shlex.quote(str(captures['n4']))}"
        # The stub seam returns the exit code directly; the real run
        # captures 5gcap's report so detect-kpi's stdout stays clean.
        if runner is None:
            result = subprocess.run(command, shell=True,
                                    capture_output=True, text=True)
        else:
            result = runner(command, shell=True)
        code = getattr(result, "returncode", result)
        if code != 0:
            detail = (getattr(result, "stderr", "") or "").strip()
            suffix = f": {detail}" if detail else ""
            raise ValueError(f"5gcap analyze failed (exit {code}){suffix}")
        with open(tmp.name) as f:
            export = json.load(f)
        if "kpis" not in export:  # e.g. an N4-only capture has no N2 KPIs
            raise ValueError("5gcap export has no kpis")
        return export
    finally:
        Path(tmp.name).unlink(missing_ok=True)


def run_kpi_agent(captures: dict, runner=None) -> list[dict]:
    """The KPI specialist node: analyze, compare, emit grounded Evidence
    items. No N2 capture, or any analyze/compare failure, yields nothing —
    never an invented item."""
    if not captures.get("n2"):
        return []
    try:
        export = run_analyze(captures, runner)
        devs = deviations(export["kpis"], load_golden(), export.get("flows", []),
                          export.get("n4", {}), export.get("sbi", {}))
        if not devs:
            return []
        _, end = capture_window(export)
    except (ValueError, OSError):
        return []
    return kpi_evidence(devs, export["kpis"], end)


def detect_kpi(captures: dict, runner=None) -> dict | None:
    """The detect-kpi comparator: the Alarm event when degraded, else None."""
    # Captures may arrive as Paths; the event and its incident-id digest
    # must be JSON-ready strings.
    captures = {k: str(v) for k, v in captures.items() if v}
    export = run_analyze(captures, runner)
    golden = load_golden()
    devs = deviations(export["kpis"], golden, export.get("flows", []),
                      export.get("n4", {}), export.get("sbi", {}))
    if not devs:
        return None
    start, end = capture_window(export)
    digest = hashlib.sha256(
        json.dumps({"captures": captures, "window_end": end},
                   sort_keys=True).encode()).hexdigest()[:8]
    return alarm_event(devs, export["kpis"], captures, f"inc-kpi-{digest}",
                       end, (start, end))
