# RabitLogic/mjwt — JWT library for MoonBit

A JSON Web Token (JWT) library written in **pure MoonBit**, with extensible
trait-based signer architecture.  Passes **58 unit tests** and is
[cross-validated](examples/exact_validate.py) against a Python reference
implementation — HMAC, ECDSA and RSA tokens are verified to interoperate.

See [SECURITY.md](SECURITY.md) for the threat model and hardening notes.

> Requires MoonBit **v0.10.4+** (uses `extend` syntax for explicit trait method
> mounting; the old implicit method mounting behavior from v0.10.3 and earlier
> is deprecated in this version).

## Features

| Algorithm | Type            | Hash       | Test coverage |
|-----------|-----------------|------------|---------------|
| **HS256** | HMAC symmetric  | SHA-256    | ✅ RFC 4231   |
| **HS384** | HMAC symmetric  | SHA-384†   | ✅ RFC 4231   |
| **HS512** | HMAC symmetric  | SHA-512†   | ✅ RFC 4231   |
| **RS256** | RSA PKCS#1 v1.5 | SHA-256    | ✅ sign + verify |
| **ES256** | ECDSA           | SHA-256    | ✅ sign + verify |

† SHA-384 / SHA-512 are self-implemented per **FIPS 180-4** and verified with
NIST known-answer tests (empty, short, multi-block) and RFC 4231 HMAC vectors.

## Quick start

```moonbit nocheck
let claims = JwtClaims::new()
claims.set_subject("user123")

// --- HS256 convenience ---
let token = @mjwt.encode(claims, "my-secret")
let decoded = @mjwt.decode(token, "my-secret")
@mjwt.verify(token, "my-secret")  // true

// Inspect without verification (debugging/diagnostic use only)
let raw = @mjwt.decode_without_verify(token)
raw.claims.get_subject()  // Some("user123")
```

### Trait-based API (extensible)

```moonbit nocheck
///|
let signer = HmacSigner::new("HS256", "my-secret")

///|
let verifier = HmacVerifier::new("HS256", "my-secret")

///|
let token = @mjwt.encode_with(signer, claims)

///|
let decoded = @mjwt.decode_with(verifier, token)
```

### Expiration check

```moonbit nocheck
claims.set_expiration(1_800_000_000L)
claims.is_expired()     // false
claims.is_now_valid()   // true
```

## Supported algorithms

### HS256 / HS384 / HS512 (HMAC)

Symmetric signing — same key for sign & verify.

```moonbit nocheck
let s = HmacSigner::new("HS256", "my-secret")?
let v = HmacVerifier::new("HS256", "my-secret")?
```

Uses MoonBit's `@crypto.hmac` with `@crypto.SHA256` (built-in) for HS256,
and with our own `Sha384` / `Sha512` (FIPS 180-4) for HS384 / HS512.

### RS256 (RSA PKCS#1 v1.5)

Asymmetric signing — private key signs, public key verifies.

```moonbit nocheck
let signer   = RsaSigner::new(n_bytes, d_bytes, "RS256")?
let verifier = RsaVerifier::new(n_bytes, e_bytes, "RS256")?
let token    = @mjwt.encode_with(signer, claims)?
let decoded  = @mjwt.decode_with(verifier, token)?
```

Key material: big-endian byte arrays for `n` (modulus), `d` (private exponent),
`e` (public exponent).  Minimum key size: 2048 bits for RS256.

> `RsaSigner::sign` uses **RSA blinding** (a fresh random `r` per signature,
> computing `(m·r^e)^d · r⁻¹ mod n`) to harden the private-key operation
> against timing side channels. `e` defaults to 65537 and can be overridden:
>
> ```moonbit nocheck
> RsaSigner::new(n, d, "RS256")               // e = 65537 (default)
> RsaSigner::new(n, d, "RS256", e_bytes=...)  // custom exponent
> ```

### ES256 (ECDSA P-256)

Asymmetric signing using the NIST P-256 (secp256r1) curve.

```moonbit nocheck
let signer   = EcSigner::new_p256(priv_bytes, pub_bytes)?
let verifier = EcVerifier::new_p256(pub_bytes)?
let token    = @mjwt.encode_with(signer, claims)?
```

Key format: 32-byte private key, 64-byte uncompressed public key (x ‖ y).

> ES256 is fully round-trip tested (sign + verify) and its signatures are
> cross-validated against Python's `cryptography` (P-256, P1363 `r‖s` format).
>
> - The nonce `k` is generated with **standard RFC 6979** (HMAC_DRBG, §3.2),
>   validated against the RFC's published P-256/SHA-256 test vectors (A.2.5).
> - Scalar multiplication uses a **Montgomery ladder** (constant operation
>   sequence per bit).
> - Signatures are normalized to **low-S**; verifiers reject high-S and
>   reject public keys that are not on the curve.

## Standard claims API

| Method | Claim | RFC 7519 |
|--------|-------|----------|
| `set_subject` / `get_subject` | `sub` | §4.1.2 |
| `set_issuer` / `get_issuer` | `iss` | §4.1.1 |
| `set_audience` / `get_audience` | `aud` (string) | §4.1.3 |
| `set_audiences` / `get_audiences` | `aud` (string-or-array) | §4.1.3 |
| `set_expiration` / `get_expiration` | `exp` | §4.1.4 |
| `set_not_before` / `get_not_before` | `nbf` | §4.1.5 |
| `set_issued_at` / `get_issued_at` | `iat` | §4.1.6 |
| `set_jwt_id` / `get_jwt_id` | `jti` | §4.1.7 |
| `is_expired` | — | Checks `exp` against `@env.now()` |
| `is_expired_with_leeway` | — | `is_expired` + clock-skew tolerance (seconds) |
| `is_now_valid` | — | Checks both `nbf` and `exp` |
| `is_now_valid_with_leeway` | — | `is_now_valid` + clock-skew tolerance (seconds) |
| `set` / `get` | arbitrary | Any custom key-value |

> `exp` / `nbf` / `iat` are stored as `Int64` and serialized with their exact
> decimal representation, so values above `2^53` (beyond `Double` precision)
> survive encode → decode round-trips losslessly.
> `aud` supports both the single-string and the RFC 7519 array form via
> `set_audiences` / `get_audiences`.

## Package layout

The library is split into a **core package** plus per-algorithm sub-packages:

```
mjwt/                core + HMAC + HS256 convenience   (alias `@mjwt`)
  mjwt.mbt           traits, errors, claims, token, Base64URL, public API
  mjwt_signer_hmac.mbt
  hash/              SHA-384 / SHA-512                  (alias `@mjwt/hash`)
  rsa/               RsaSigner / RsaVerifier            (alias `@mjwt/rsa`)
  ecdsa/             EcSigner / EcVerifier (P-256)      (alias `@mjwt/ecdsa`)
```

- Core API (`@mjwt.encode/decode/verify`, `@mjwt.encode_with/decode_with`,
  `@mjwt.JwtClaims`, `@mjwt.HmacSigner`) lives in the root package.
- RSA and ECDSA signers live in their own packages:
  `@mjwt/rsa.RsaSigner`, `@mjwt/ecdsa.EcSigner`, etc.
- SHA-384/512 helpers live in `@mjwt/hash` (`@mjwt/hash.sha384`, …).

> **Migration note (v0.2 → v0.3):** `RsaSigner`, `RsaVerifier`, `EcSigner`,
> `EcVerifier` moved from `@mjwt.*` to `@mjwt/rsa.*` / `@mjwt/ecdsa.*`; the
> `sha384`/`sha512` helpers and `Sha384`/`Sha512` moved to `@mjwt/hash.*`. The
> core HS256 API is unchanged.

## Architecture

```
                      ┌──────────────────────┐
                      │   JwtSigner trait     │
                      │   JwtVerifier trait   │
                      └──────────┬───────────┘
                                 │ implements
           ┌─────────────────────┼──────────────────────┐
           ▼                     ▼                      ▼
    HmacSigner              RsaSigner               EcSigner
    HmacVerifier            RsaVerifier             EcVerifier
    (HS256/384/512)         (RS256)                 (ES256 P-256)
```

### File structure

| Path | Responsibility |
|------|---------------|
| `mjwt.mbt` | Core: errors, traits, `JwtHeader`, `JwtClaims`, `JwtToken`, Base64URL, public API |
| `mjwt_signer_hmac.mbt` | `HmacSigner` / `HmacVerifier` |
| `hash/sha512.mbt` | SHA-384 / SHA-512 (FIPS 180-4, `@crypto.CryptoHasher`) |
| `rsa/rsa.mbt` | `RsaSigner` / `RsaVerifier` (blinded signing) |
| `ecdsa/ecdsa.mbt` | `EcSigner` / `EcVerifier` (P-256, RFC 6979, low-S) |
| `mjwt_test.mbt` | 24 core unit tests |
| `mjwt_wbtest.mbt` | 8 core whitebox tests |
| `mjwt_fuzz_test.mbt` | 5 robustness tests (malformed-input fuzz stand-in) |
| `mjwt_bench_test.mbt` | 2 core benchmarks |
| `hash/sha512_test.mbt` | 7 SHA KAT tests |
| `rsa/rsa_test.mbt` + `rsa/rsa_wbtest.mbt` | 6 RSA tests (round-trip, blinding, min key) |
| `ecdsa/ecdsa_test.mbt` + `ecdsa/ecdsa_wbtest.mbt` | 8 ECDSA tests (RFC 6979, low-S, point check) |
| `SECURITY.md` | Threat model, mitigations, residual risks |
| `examples/example_usage.mbt` | Runnable usage examples (12 tests) |
| `examples/py_compare.py` | Python cross-validation script |

## Adding a custom signer

Implement the `JwtSigner` / `JwtVerifier` traits on any type, and use `extend`
to expose trait methods via dot syntax (required since MoonBit v0.10.4):

```moonbit nocheck
struct MySigner { key : Bytes }
impl JwtSigner for MySigner with fn alg_name(_) -> String { "HS256" }
impl JwtSigner for MySigner with fn sign(self, msg) -> .. { .. }

// Mount trait methods as dot-syntax methods on MySigner
pub extend MySigner with JwtSigner::{alg_name, sign}

let token = @mjwt.encode_with(MySigner { key }, claims)
```

## Development

```bash
moon test              # run 58 tests (all packages)
moon bench             # run 5 benchmarks (all packages)
moon check             # check for warnings
moon coverage analyze  # code coverage
moon fmt               # format code
moon info              # update interface (.mbti) files
```

## Cross-validation

```bash
# Full interop test (Python + MoonBit)
python3 examples/exact_validate.py

# Legacy format check
python3 examples/py_compare.py
```

## Performance

| Algorithm | Operation    | Time (mean ± σ)        | Notes                  |
|-----------|-------------|------------------------|------------------------|
| **HS256** | encode      | `4.5 µs`               |                        |
| **HS256** | decode      | `4.8 µs`               |                        |
| **RS256** | sign        | `~26 ms`           | blinded (constant-time hardening) |
| **ES256** | sign        | `~2.6 ms`          | RFC 6979 k + Montgomery ladder |
| **ES256** | verify      | `~5.4 ms`          | ladder + low-S + point check |

> ES256 uses native `@bigint.BigInt` field arithmetic with Jacobian projective
> coordinates, roughly **60× faster** than the previous pure-MoonBit limb
> implementation, with a deterministic RFC 6979 nonce and a Montgomery ladder
> for constant-time scalar multiplication.
> Run benchmarks: `moon bench`

## License

MIT