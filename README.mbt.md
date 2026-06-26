# RabitLogic/mjwt — JWT library for MoonBit

A JSON Web Token (JWT) library written in pure MoonBit, with extensible
trait-based signer architecture.

## Features

| Algorithm | Type     | Status |
|-----------|----------|--------|
| **HS256** | HMAC-SHA256 | ✅ |
| **HS384** | HMAC-SHA384 | ✅ |
| **HS512** | HMAC-SHA512 | ✅ |
| **RS256** | RSA PKCS#1 v1.5 | 🟢 code ready |
| **ES256** | ECDSA P-256 | 🟢 code ready |

## Quick start

```moonbit nocheck
let claims = JwtClaims::new()
claims.set_subject("user123")

// --- HS256 convenience ---
let token = @mjwt.encode(claims, "my-secret")
let decoded = @mjwt.decode(token, "my-secret")
@mjwt.verify(token, "my-secret")  // true

// --- Trait-based (extensible) ---
let signer   = HmacSigner::new("HS256", "my-secret")
let verifier = HmacVerifier::new("HS256", "my-secret")
let token2   = @mjwt.encode_with(signer, claims)
let decoded2 = @mjwt.decode_with(verifier, token2)
```

## Architecture

```
                     ┌─────────────────────┐
                     │   JwtSigner trait    │
                     │   JwtVerifier trait  │
                     └────────┬────────────┘
                              │ implemented by
          ┌───────────────────┼────────────────────┐
          ▼                   ▼                    ▼
   HmacSigner           RsaSigner             EcSigner
   HmacVerifier         RsaVerifier           EcVerifier
   (HS256/384/512)      (RS256)               (ES256)
```

### File structure

| File | Responsibility |
|------|---------------|
| `mjwt.mbt` | Core: errors, traits, `JwtHeader`, `JwtClaims`, `JwtToken`, encoding, public API |
| `mjwt_hash_sha512.mbt` | SHA-384 / SHA-512 implementations (`CryptoHasher`) |
| `mjwt_signer_hmac.mbt` | `HmacSigner` / `HmacVerifier` (symmetric HMAC) |
| `mjwt_signer_rsa.mbt`  | `RsaSigner` / `RsaVerifier` (asymmetric RSA PKCS#1 v1.5) |
| `mjwt_signer_ecdsa.mbt` | `EcSigner` / `EcVerifier` (asymmetric ECDSA P-256) |

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
moon test              # run tests
moon fmt               # format code
moon info              # update interface files
```

## License

Apache-2.0