# Use pycrate for ASN.1 decoding, scapy for packet I/O

We're building a 5G control-plane capture analyzer with zero capture tooling on the machine: tshark/wireshark are not installed, and installing them requires apt. We chose **scapy** (pip-installable via uv, Python-native) over pyshark (wraps tshark, unavailable here) and over hand-written dissectors (NGAP is ASN.1-PER; from-scratch decoding is a project in itself). scapy ships NGAP / NAS-5G / PFCP layer scaffolds to extend.

## Status

accepted — **amended** (same session, first implementation fact-check): scapy 2.7.0 ships **no NGAP and no NAS-5G** modules at all (only `scapy.contrib.pfcp`). The decoding core therefore uses **pycrate 0.8.1** (pure pip): `pycrate_asn1dir.NGAP` for NGAP, `pycrate_mobile` (TS24501_FGMM/FGSM) for NAS-5G, `pycrate_mobile.TS29244_PFCP` for PFCP. scapy's role is packet I/O and SCTP transport handling.

## Considered Options

- **pyshark**: excellent dissectors, but requires apt-installing the tshark toolchain — an external, non-pip dependency we can't assume on other machines either.
- **dpkt / from-scratch**: no 5G support; the ASN.1-PER decode work would dominate the project.

## Consequences

- Custom layer code may be needed wherever pycrate's spec versions are older than what appears in captures (spec release pinned per capture; unknown/newer IEs land in the lenient `unparsed` annotation path).
- `CryptoMobile` is not installed: NAS messages with security protection (initial Registration Request is plain, but subsequent NAS is integrity/cipher-protected) cannot be decrypted — protected payloads are surfaced as `unparsed`.
- Pure-Python decoding bounds v1 capture sizes to ~100 MB (documented in the README).
- Decode is lenient by design: unknown IEs/messages are annotated as `unparsed` rather than failing the decode.
