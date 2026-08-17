"""NAS security-header handling and cause extraction (sandbox selects 5G-EA0).

The AMF's SecurityModeCommand picks 5G-EA0 (null cipher, see the sandbox
amf.yaml `ciphering_order`), so shdr 2/4 payloads are integrity-protected but
plaintext; `decode` strips the 7-byte header and parses the inner NAS.
"""

from pycrate_mobile.TS24501_FGMM import (
    FGMMRegistrationAccept,
    FGMMRegistrationReject,
    FGMMSecurityModeCommand,
)
from pycrate_mobile.TS24501_FGSM import FGSMPDUSessionEstabReject

from fivegcap.nas import decode


def _wrap(shdr: int, inner: bytes) -> bytes:
    """Emulate a security-protected NAS PDU: EPD, sec hdr, 4-byte MAC, seq."""
    return b"\x7e" + bytes([shdr]) + b"\x01\x02\x03\x04" + b"\x00" + inner


def test_reject_cause_extraction():
    reg = FGMMRegistrationReject()
    reg[1].set_val({"V": b"\x07"})
    nas = decode(reg.to_bytes())
    assert nas.name == "5GMMRegistrationReject"
    assert nas.cause == 7
    assert nas.cause_name == "5GS services not allowed"

    pdu = FGSMPDUSessionEstabReject()
    pdu[1].set_val({"V": b"\x1b"})
    nas = decode(pdu.to_bytes())
    assert nas.name == "5GSMPDUSessionEstabReject"
    assert nas.cause == 27
    assert nas.cause_name == "Missing or unknown DNN"


def test_smc_selects_algorithms():
    smc = FGMMSecurityModeCommand()
    smc[1].set_val([[0, 2]])  # CiphAlgo 5G-EA0, IntegAlgo 5G-IA2
    nas = decode(_wrap(3, smc.to_bytes()))
    assert nas.protected
    assert nas.inner == "5GMMSecurityModeCommand"
    assert nas.ciph_algo == 0
    assert nas.integ_algo == 2


def test_ea0_protected_payload_is_plaintext():
    accept = FGMMRegistrationAccept()
    wrapped = _wrap(2, accept.to_bytes())

    nas = decode(wrapped, ciph_algo=0)
    assert nas.protected
    assert nas.inner == "5GMMRegistrationAccept"
    assert nas.unparsed is None

    # Without the SMC, ciphering is unknown: no bogus parse.
    nas = decode(wrapped)
    assert nas.inner is None
    assert "ciphering unknown" in nas.unparsed

    # A real cipher is reported, not guessed at.
    nas = decode(wrapped, ciph_algo=2)
    assert nas.inner is None
    assert "5G-EA2" in nas.unparsed
