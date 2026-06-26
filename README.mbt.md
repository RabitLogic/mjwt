# RabitLogic/mjwt — JWT library for MoonBit

A JSON Web Token (JWT) library written in **pure MoonBit**, with extensible
trait-based signer architecture.  Passes **44 unit tests** and is cross-validated
against a Python reference implementation.

## Features

| Algorithm | Type            | Hash       | Test coverage |
|-----------|-----------------|------------|---------------|
| **HS256** | HMAC symmetric  | SHA-256    | ✅ RFC 4231   |
| **HS384** | HMAC symmetric  | SHA-384†   | ✅ RFC 4231   |
| **HS512** | HMAC symmetric  | SHA-512†   | ✅ RFC 4231   |
| **RS256** | RSA PKCS#1 v1.5 | SHA-256    | ✅ format     |
| **ES256** | ECDSA           | SHA-256    | ✅ format     |

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

### ES256 (ECDSA P-256)

Asymmetric signing using the NIST P-256 (secp256r1) curve.

```moonbit nocheck
let signer   = EcSigner::new_p256(priv_bytes, pub_bytes)?
let verifier = EcVerifier::new_p256(pub_bytes)?
let token    = @mjwt.encode_with(signer, claims)?
```

Key format: 32-byte private key, 64-byte uncompressed public key (x ‖ y).

## Standard claims API

| Method | Claim | RFC 7519 |
|--------|-------|----------|
| `set_subject` / `get_subject` | `sub` | §4.1.2 |
| `set_issuer` / `get_issuer` | `iss` | §4.1.1 |
| `set_audience` / `get_audience` | `aud` | §4.1.3 |
| `set_expiration` / `get_expiration` | `exp` | §4.1.4 |
| `set_not_before` / `get_not_before` | `nbf` | §4.1.5 |
| `set_issued_at` / `get_issued_at` | `iat` | §4.1.6 |
| `set_jwt_id` / `get_jwt_id` | `jti` | §4.1.7 |
| `is_expired` | — | Checks `exp` against `@env.now()` |
| `is_now_valid` | — | Checks both `nbf` and `exp` |
| `set` / `get` | arbitrary | Any custom key-value |

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

| File | Responsibility |
|------|---------------|
| `mjwt.mbt` | Core: errors, traits, `JwtHeader`, `JwtClaims`, `JwtToken`, Base64URL, public API |
| `mjwt_hash_sha512.mbt` | SHA-384 / SHA-512 (FIPS 180-4, `@crypto.CryptoHasher`) |
| `mjwt_signer_hmac.mbt` | `HmacSigner` / `HmacVerifier` |
| `mjwt_signer_rsa.mbt` | `RsaSigner` / `RsaVerifier` |
| `mjwt_signer_ecdsa.mbt` | `EcSigner` / `EcVerifier` (P-256) |
| `mjwt_test.mbt` | 32 unit tests + 4 benchmarks (skipped by default) |
| `examples/example_usage.mbt` | Runnable usage examples (12 tests) |
| `examples/py_compare.py` | Python cross-validation script |

## Adding a custom signer

Implement the `JwtSigner` / `JwtVerifier` traits on any type:

```moonbit nocheck
struct MySigner { key : Bytes }
impl JwtSigner for MySigner with fn alg_name(_) -> String { "HS256" }
impl JwtSigner for MySigner with fn sign(self, msg) -> .. { .. }

let token = @mjwt.encode_with(MySigner { key }, claims)
```

## Development

```bash
moon test              # run 44 tests
moon bench             # run benchmarks
moon fmt               # format code
moon info              # update interface (.mbti) files

# Cross-validation
python3 examples/py_compare.py
```

## License

MIT