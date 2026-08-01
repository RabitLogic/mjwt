"""
verify_es256_interop.py — Verify a MoonBit-mjwt ES256 JWT with Python cryptography

The MoonBit library signs with RFC 6979 deterministic k. A JWT ECDSA signature
is P1363 raw (r||s, 64 bytes); `cryptography` expects DER, so we convert.
"""
import base64
import json
import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def der_sig_from_p1363(raw: bytes) -> bytes:
    """Convert P1363 r||s (64 bytes) to DER ECDSA-Sig-Value."""
    half = len(raw) // 2
    r = int.from_bytes(raw[:half], "big")
    s = int.from_bytes(raw[half:], "big")

    def enc_int(x: int) -> bytes:
        b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b

    r_enc, s_enc = enc_int(r), enc_int(s)
    return (
        b"\x30"
        + bytes([len(r_enc) + len(s_enc) + 4])
        + b"\x02"
        + bytes([len(r_enc)])
        + r_enc
        + b"\x02"
        + bytes([len(s_enc)])
        + s_enc
    )


def verify(token: str, pub_key: ec.EllipticCurvePublicKey) -> bool:
    hdr_b64, pay_b64, sig_b64 = token.split(".")
    header = json.loads(b64url_decode(hdr_b64))
    assert header["alg"] == "ES256", f"unexpected alg {header['alg']}"
    msg = f"{hdr_b64}.{pay_b64}".encode()
    raw_sig = b64url_decode(sig_b64)
    assert len(raw_sig) == 64, f"P1363 sig must be 64 bytes, got {len(raw_sig)}"
    der_sig = der_sig_from_p1363(raw_sig)
    pub_key.verify(der_sig, msg, ec.ECDSA(hashes.SHA256()))
    return True


def main() -> None:
    token = sys.argv[1] if len(sys.argv) > 1 else None
    if token is None:
        token = input("Paste ES256 JWT: ").strip()
    # Public key (x||y, 64 bytes) matching the MoonBit test private key.
    pub_hex = (
        "cbba22aa20546bdfc2c4bda6786eef83e335206aa1cd57cb94501c3ce4778dc0"
        "1884a2dd566365464366148f69ec76bacbf1530c95cc81fc766746f8145637d0"
    )
    pub_bytes = b"\x04" + bytes.fromhex(pub_hex)  # SEC1: 0x04 || x || y
    pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), pub_bytes
    )
    header = json.loads(b64url_decode(token.split(".")[0]))
    print(f"header.alg        : {header['alg']}")
    print(f"payload           : {b64url_decode(token.split('.')[1]).decode()}")
    verify(token, pub_key)
    print("ES256 signature   : ✅ VALID (verified with Python cryptography)")


if __name__ == "__main__":
    main()
