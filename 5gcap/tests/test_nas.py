"""NAS security-header handling and cause extraction (sandbox selects 5G-EA0).

The AMF's SecurityModeCommand picks 5G-EA0 (null cipher, see the sandbox
amf.yaml `ciphering_order`), so shdr 2/4 payloads are integrity-protected but
plaintext; `decode` strips the 7-byte header and parses the inner NAS.
"""

from pycrate_mobile.TS24501_FGMM import (
    FGMMRegistrationAccept,
    FGMMRegistrationReject,
    FGMMRegistrationRequest,
    FGMMSecurityModeCommand,
)
from pycrate_mobile.TS24501_FGSM import FGSMPDUSessionEstabReject
from pycrate_mobile.TS24501_IE import FGSID

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


def _reg_with_5gsid(vals: list) -> bytes:
    """A RegistrationRequest whose 5GS mobile identity IE carries `vals`
    (the FGSID envelope's set_val list shape)."""
    fgsid = FGSID()
    fgsid.set_val(vals)
    reg = FGMMRegistrationRequest()
    reg[3]["V"].set_val(fgsid.to_bytes())
    return reg.to_bytes()


def test_null_scheme_suci_normalizes_to_supi():
    # ProtSchemeID 0 = null: the "output" is the plaintext BCD MSIN, so the
    # SUCI is plaintext SUPI (PLMN 999-70 + MSIN 0000000002) and joins.
    suci = [0, 0, 0, 1, [b"\x99\xf9\x07", b"\x00\x00", 0, 0, 0,
                          b"\x00\x00\x00\x00 "]]
    nas = decode(_reg_with_5gsid(suci))
    assert nas.name == "5GMMRegistrationRequest"
    assert nas.supi == "999700000000002"
    assert nas.guti is None
    assert nas.unparsed is None


def test_protected_suci_yields_no_supi():
    # ProtSchemeID 1 (ECIES profile A): the output is ciphertext — never
    # guessed, never joined.
    suci = [0, 0, 0, 1, [b"\x99\xf9\x07", b"\x00\x00", 0, 1, 0,
                          [b"\xaa" * 32, b"\xbb" * 8, b"\xcc" * 8]]]
    nas = decode(_reg_with_5gsid(suci))
    assert nas.name == "5GMMRegistrationRequest"
    assert nas.supi is None and nas.guti is None
    assert nas.unparsed is None


def test_guti_extracted_as_evidence():
    # 5G-GUTI: honest evidence, never a join key.
    guti = [0xF, 0, 2, b"\x99\xf9\x07", 1, 63, 21, 0xDEADBEEF]
    nas = decode(_reg_with_5gsid(guti))
    assert nas.name == "5GMMRegistrationRequest"
    assert nas.guti == "99970-1-63-21-3735928559"
    assert nas.supi is None
