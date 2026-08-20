"""5gcap CLI: single-pass capture analysis."""

import argparse
import sys

from .capture import read_capture, read_pfcp_capture
from .correlate import correlate
from .ngap import decode as ngap_decode
from .pfcp import decode as pfcp_decode
from .sbi import read_sbi_capture
from .flow import build_flows
from .kpi import compute
from .output import (print_trace, write_json, write_merged_json,
                     print_pfcp_trace, write_pfcp_json, print_sbi_trace,
                     write_sbi_json)


def analyze(path: str, json_out: str | None,
            sbi_path: str | None = None,
            n4_path: str | None = None) -> int:
    raw = read_capture(path)
    if raw:
        msgs = [ngap_decode(m.ts, m.assoc, m.stream, m.data, m.src_ip, m.dst_ip)
                for m in raw]
        flows, unassociated = build_flows(msgs)
        kpi = compute(flows)
        print_trace(flows, kpi, unassociated)
        if sbi_path or n4_path:
            # Merged run: the other captures are the same run's other planes.
            sbi_msgs = read_sbi_capture(sbi_path) if sbi_path else None
            n4_msgs = ([pfcp_decode(m.ts, m.data, m.src_ip, m.dst_ip,
                                    m.src_port, m.dst_port)
                        for m in read_pfcp_capture(n4_path)]
                       if n4_path else None)
            corr = correlate(flows, sbi_msgs=sbi_msgs, n4_msgs=n4_msgs)
            if json_out:
                write_merged_json(flows, kpi, unassociated, corr, json_out,
                                  sbi_msgs=sbi_msgs, n4_msgs=n4_msgs)
                print(f"JSON written to {json_out}")
            return 0
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
    sbi_raw = read_sbi_capture(path)
    if sbi_raw:
        print_sbi_trace(sbi_raw)
        if json_out:
            write_sbi_json(sbi_raw, json_out)
            print(f"JSON written to {json_out}")
        return 0
    print(f"error: no NGAP, PFCP, or SBI messages found in {path}")
    return 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="5gcap", description="5G control-plane PCAP analyzer")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("analyze", help="decode a capture and compute KPIs")
    p.add_argument("capture", help="path to a .pcap/.pcapng file")
    p.add_argument("--json", dest="json_out", default=None, help="write structured JSON to this path")
    p.add_argument("--sbi", dest="sbi_path", default=None,
                   help="path to an SBI (HTTP/2) capture of the same run; "
                        "correlated and merged into the JSON export")
    p.add_argument("--n4", dest="n4_path", default=None,
                   help="path to an N4 (PFCP) capture of the same run; "
                        "correlated and merged into the JSON export")
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])
    if args.cmd == "analyze":
        return analyze(args.capture, args.json_out,
                       sbi_path=args.sbi_path, n4_path=args.n4_path)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
