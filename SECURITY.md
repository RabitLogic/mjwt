# Security

## Reporting a vulnerability

Please do **not** open a public issue. Report security findings privately to the
maintainers (open a private advisory / contact the repo owner) with a proof of
concept and the MoonBit version used.

## Threat model

`mjwt` is a JWT **signing and verification** library. It assumes:

- **Signers hold private keys on a trusted machine.** The signing side must run
  in an environment the operator controls; it should **not** be exposed to
  untrusted multi-tenant code or shared hardware unless the mitigations below
  are considered sufficient.
- **Verifiers are exposed to untrusted tokens.** All `decode`/`verify` entry
  points are hardened against malformed input (no panics, clean `JwtError`).
- **The host platform is trusted** (no malicious OS/hypervisor), and the process
  does not leak secrets through logs, core dumps, or swap.

## Mitigations implemented

| Area | Status |
|------|--------|
| HMAC comparison | Constant-time (XOR-accumulate `diff == 0`), no early exit on content |
| RSA verify comparison | Constant-time EM decoding (XOR-accumulate over all bytes) |
| RSA sign (private op) | **Blinded** with a fresh random `r` per signature: `s = ((m·r^e)^d)·r⁻¹ mod n`; `r` drawn from OS entropy (`@random.Rand::new()` → `@env.rand`) |
| ECDSA scalar mult | **Montgomery ladder** — one add + one double per bit, operation count independent of the scalar |
| ECDSA nonce `k` | Deterministic **RFC 6979** (HMAC_DRBG), validated against the RFC's published A.2.5 vectors |
| ECDSA low-S | Sign normalizes to low-S; verify rejects high-S |
| Public-key validation | `EcVerifier`/`EcSigner` reject points not on the P-256 curve and out-of-range private scalars |
| Algorithm confusion | `decode_with` rejects tokens whose header `alg` differs from the verifier's algorithm |
| RSA minimum key size | Signers and verifiers reject moduli < 2048 bits |
| Number precision | `exp`/`nbf`/`iat` preserved as exact `Int64` (>2^53) via JSON `repr`; strict core `@json.parse` |
| Malformed input | Fuzz-style robustness tests: random/huge/malformed tokens never panic (see `mjwt_fuzz_test.mbt`) |

## Important caveat: MoonBit `BigInt` side channels

The private-key operations still run on MoonBit's `@bigint.BigInt`, which is a
**general-purpose** big-integer implementation:

- `BigInt::pow` is square-and-multiply (not constant-time at the limb level).
- RSA **blinding** and the ECDSA **ladder** remove the *algorithm-level* timing
  dependence on the key/scalar bits, but they do **not** guarantee
  microarchitectural-level constant time (cache/branch-prediction leaks inside
  BigInt's multiplication are still theoretically possible).

For deployments where the attacker can run code on the same CPU as the signer
(co-tenancy, cloud VMs with fine-grained timing), prefer:
- signing inside an HSM / secure enclave, or
- a constant-time, audited crypto backend for the private-key operations.

## Known MoonBit core bug (worked around)

`@bigint.BigInt::from_octets` returns a **non-canonical zero** (`len > 0` with
all-zero limbs) when given an all-zero byte string. This breaks `==`, `<`, and
`to_string` on that value, and would silently defeat the `r=0` / `s=0` / `d=0`
rejection checks (a potential forgery surface).

**Workaround:** every byte-to-`BigInt` conversion routes through a private
`bi_from_octets` helper (one copy in `ecdsa/ecdsa.mbt`, one in `rsa/rsa.mbt`),
which returns the canonical `0N` for all-zero input. This covers every
conversion site (scalars, RFC 6979 candidates, RSA key material), and the
regression tests in `ecdsa/ecdsa_wbtest.mbt` / `rsa/rsa_wbtest.mbt` fail or
crash without it. If the core library fixes this, the workaround can be removed
by changing `bi_from_octets` to delegate directly.

**Upstream:** this should be fixed in `moonbitlang/core` (`bigint_nonjs.mbt`,
`BigInt::from_octets`: normalize the all-zero case so `len == 0` / `limbs == [0]`).
A minimal repro:
```moonbit
let z = @bigint.BigInt::from_octets(b"\x00\x00\x00\x00")
println(z.to_string()) // panics in current core
```
Please file this against the MoonBit core repo; the fix is one `if` in
`from_octets` (return the canonical `zero` when all limbs are zero).

## Version policy

This is a `0.x` library. Treat the API as unstable until `1.0.0`. No formal
security audit has been performed; the mitigation table above and the test
suite are the current assurance.
