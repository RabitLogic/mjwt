"""Verify MoonBit-mjwt ES256 + RS256 JWTs with Python cryptography (interop)."""
import base64
import json
import sys
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes

ES_TOKEN = (
    "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJlczI1Ni1pbnRlcm9wIn0."
    "eN__zHIL0nfWvcVrPJWUhvV2sO_1mRHb9dLQIOVkZHV4BCYD_dnaYujJaFtRz6tHB34guES7vwGyFUK"
    "eIf4agA"
)
RS_TOKEN = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJyczI1Ni1pbnRlcm9wIn0."
    "uaL6XJlcUlfbv51evtOvEjkGYOxJJpH9wVNBzTcKzg-DJiE6eC5VZCMz0ZAnUaqLHID5pQYfUJc22TH"
    "QMgJjtGVkqjb_7f9Wxp4hQyUE_HsoIqznnRiGc_q9oq6s-ojwdEcbPd0tNtSHtRlF9nwmtAOUfIZKzI9"
    "DCnj7aNZfz5RpSiaAL2psTRI10iqRpw7ze3sAJRqJQiWOR4rx8J_PvZ55YpLelIYCOQsLlblmMT-cD-8"
    "D0G9d6CiYSPVVttHLZNl9E5eTS7mYiyIpdV3qurmylQJSXkOTpvOj6a86kHPlqR86VinQ2mWwMaOEpbc"
    "HkYgjsG2xkWymXww3CBVo_w"
)

# P-256 private key (matching the MoonBit test key) for low-S computation.
EC_PRIV = int(
    "f5a10e3be8aa44f377955a55a8998b282437886a65078f1125b715907f7f6a7b", 16
)
N = int(
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16
)


def b64d(s):
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def p1363_to_der(raw):
    half = len(raw) // 2
    r, s = int.from_bytes(raw[:half], "big"), int.from_bytes(raw[half:], "big")

    def enc(x):
        b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
        return b"\x00" + b if b[0] & 0x80 else b

    re_, se = enc(r), enc(s)
    return b"\x30" + bytes([len(re_) + len(se) + 4]) + b"\x02" + bytes(
        [len(re_)]
    ) + re_ + b"\x02" + bytes([len(se)]) + se


# --- ES256 ---
pub = ec.EllipticCurvePublicKey.from_encoded_point(
    ec.SECP256R1(),
    b"\x04"
    + bytes.fromhex(
        "cbba22aa20546bdfc2c4bda6786eef83e335206aa1cd57cb94501c3ce4778dc0"
        "1884a2dd566365464366148f69ec76bacbf1530c95cc81fc766746f8145637d0"
    ),
)
hdr, pay, sig = ES_TOKEN.split(".")
assert json.loads(b64d(hdr))["alg"] == "ES256"
raw_sig = b64d(sig)
s_val = int.from_bytes(raw_sig[32:], "big")
print(f"ES256: s = {s_val:064x}")
print(f"ES256: low-S (s <= n/2) = {s_val <= N // 2}")
pub.verify(p1363_to_der(raw_sig), f"{hdr}.{pay}".encode(), ec.ECDSA(hashes.SHA256()))
print("ES256: signature ✅ VALID")

# --- RS256 ---
n = int(
    "bdd7d4fa99a5f4b2a4c3b5090abd12363e087a1885220843cfec1c0562aae4e588f3afd138d96f2444e288943673725d7bda86b4c01c0353557c6f57c55e479f54731a415daed140b163c63ab83de8ed67150795846878599cd97297b431ea3787d8c4ce21d95e1305b8fae4ada9b47ef7f09b6718d27eae1347f5329309f3b601855e3d0bdb065fe4f7dc767a728966581c5e85b45df6480ee98094a3debfddf3ca89878afd3bd6fa56b0304ed40660009c190b04d94b8774fbef5799c3c074ab8f29128c5ad4d94432e4d1be200abdd5a117de35b2c7bbaeabec48b86750adc0529bd5b3cd4edd2ea4d5ae6b0d0d917b147c49c330929c8f8315d702f6be11",
    16,
)
e = 65537
pub_rsa = rsa.RSAPublicNumbers(e, n).public_key()
hdr, pay, sig = RS_TOKEN.split(".")
assert json.loads(b64d(hdr))["alg"] == "RS256"
pub_rsa.verify(
    b64d(sig),
    f"{hdr}.{pay}".encode(),
    padding.PKCS1v15(),
    hashes.SHA256(),
)
print("RS256: signature ✅ VALID (blinded signer unblinds to correct PKCS#1 v1.5)")
print("ALL INTEROP CHECKS PASSED")
