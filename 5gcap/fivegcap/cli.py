"""5gcap CLI: single-pass capture analysis."""

import argparse
import sys

from .capture import read_capture, read_pfcp_capture
from .ngap import decode as ngap_decode
from .pfcp import decode as pfcp_decode
from .flow import build_flows
from .kpi import compute
from .output import print_trace, write_json, print_pfcp_trace, write_pfcp_json


def analyze(path: str, json_out: str | None) -> int:
    raw = read_capture(path)
    if raw:
        msgs = [ngap_decode(m.ts, m.assoc, m.stream, m.data, m.src_ip, m.dst_ip)
                for m in raw]
        flows, unassociated = build_flows(msgs)
        kpi = compute(flows)
        print_trace(flows, kpi, unassociated)
        if json_out:
            write_json(flows, kpi, unassociated, json_out)
            print(f"JSON written to {json_out}")
        return 0
    pfcp_raw = read_pfcp_capture(path)
    if pfcp_raw:
        pfcp_msgs = [pfcp_decode(m.ts, m.data, m.src_ip, m.dst_ip, m.src_port, m.dst_port)
                     for m in pfcp_raw]
        print_pfcp_trace(pfcp_msgs)
        if json_out:
            write_pfcp_json(pfcp_msgs, json_out)
            print(f"JSON written to {json_out}")
        return 0
    print(f"error: no NGAP or PFCP messages found in {path}")
    return 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="5gcap", description="5G control-plane PCAP analyzer")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("analyze", help="decode a capture and compute KPIs")
    p.add_argument("capture", help="path to a .pcap/.pcapng file")
    p.add_argument("--json", dest="json_out", default=None, help="write structured JSON to this path")
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])
    if args.cmd == "analyze":
        return analyze(args.capture, args.json_out)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
