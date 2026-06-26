///|
/// # mjwt — Complete usage examples
///
/// This file demonstrates every public API of the mjwt library through
/// runnable test cases.  Copy-paste these patterns into your own project.
///
/// ## How to run
///
/// ```bash
/// moon test --target native
/// ```
///
/// See `examples/py_compare.py` for cross-validation against Python's JWT.

// =============================================================================
//  1. Quick start — HS256 encode / decode
// =============================================================================

///|
test "ex01 HS256 quick start" {
  let claims = JwtClaims::new()
  claims.set_subject("user123")
  claims.set_issuer("moonbit-app")

  // Encode
  let token = @mjwt.encode(claims, "my-secret-key")
  @test.assert_not_eq(token.length(), 0)

  // Decode and verify signature
  let decoded = @mjwt.decode(token, "my-secret-key")
  @test.assert_eq(decoded.header.alg, "HS256")
  @test.assert_eq(decoded.header.typ, "JWT")
  @test.assert_eq(decoded.claims.get_subject(), Some("user123"))
  @test.assert_eq(decoded.claims.get_issuer(), Some("moonbit-app"))
}

// =============================================================================
//  2. Trait-based generic API — custom Signer / Verifier
// =============================================================================

///|
test "ex02 trait generic API" {
  let signer = HmacSigner::new("HS256", "shared-secret") catch { e => raise e }
  let verifier = HmacVerifier::new("HS256", "shared-secret") catch { e => raise e }

  let claims = JwtClaims::new()
  claims.set_subject("trait-test")

  let token = @mjwt.encode_with(signer, claims)
  let decoded = @mjwt.decode_with(verifier, token)

  @test.assert_eq(decoded.header.alg, "HS256")
  @test.assert_eq(decoded.claims.get_subject(), Some("trait-test"))
}

// =============================================================================
//  3. All standard JWT claims
// =============================================================================

///|
test "ex03 standard claims" {
  let c = JwtClaims::new()
  c.set_subject("sub")           // sub  — subject
  c.set_issuer("iss")            // iss  — issuer
  c.set_audience("aud")          // aud  — audience
  c.set_jwt_id("jti")            // jti  — JWT ID
  c.set_issued_at(1_700_000_000L) // iat — issued at
  c.set_expiration(1_800_000_000L) // exp — expiration
  c.set_not_before(1_600_000_000L) // nbf — not before

  let token = @mjwt.encode(c, "secret")

  // Inspect without verification (not trusted, debugging only)
  let raw = @mjwt.decode_without_verify(token)
  @test.assert_eq(raw.claims.get_subject(), Some("sub"))
  @test.assert_eq(raw.claims.get_expiration(), Some(1_800_000_000L))

  // Decode and verify
  let d = @mjwt.decode(token, "secret")
  @test.assert_eq(d.claims.get_subject(), Some("sub"))
  @test.assert_eq(d.claims.get_issuer(), Some("iss"))
  @test.assert_eq(d.claims.get_audience(), Some("aud"))
  @test.assert_eq(d.claims.get_jwt_id(), Some("jti"))
  @test.assert_eq(d.claims.get_issued_at(), Some(1_700_000_000L))
  @test.assert_eq(d.claims.get_expiration(), Some(1_800_000_000L))
  @test.assert_eq(d.claims.get_not_before(), Some(1_600_000_000L))
}

// =============================================================================
//  4. Custom claims
// =============================================================================

///|
test "ex04 custom claims" {
  let c = JwtClaims::new()
  c.set("role", Json::string("admin"))
  c.set("score", Json::number(99.5))
  c.set("active", Json::bool(true))

  let token = @mjwt.encode(c, "my-key")
  let d = @mjwt.decode(token, "my-key")

  match d.claims.get("role") {
    Some(String(s)) => @test.assert_eq(s, "admin")
    _ => @test.fail("")
  }
  match d.claims.get("score") {
    Some(Number(n, ..)) => @test.assert_eq(n, 99.5)
    _ => @test.fail("")
  }
  match d.claims.get("active") {
    Some(Bool(b)) => @test.assert_eq(b, true)
    _ => @test.fail("")
  }
}

// =============================================================================
//  5. Token verification (returns bool, no panic)
// =============================================================================

///|
test "ex05 safe verify" {
  let token = @mjwt.encode(JwtClaims::new(), "correct-secret")
  @test.assert_eq(@mjwt.verify(token, "correct-secret"), true)
  @test.assert_eq(@mjwt.verify(token, "wrong-secret"), false)
  @test.assert_eq(@mjwt.verify("not-a-token", "secret"), false)
}

// =============================================================================
//  6. Expiration check
// =============================================================================

///|
test "ex06 expiration check" {
  let c = JwtClaims::new()
  // No exp set → is_expired = false
  @test.assert_eq(c.is_expired(), false)
  @test.assert_eq(c.is_now_valid(), true)

  // Past timestamp → expired
  c.set_expiration(1_000_000_000L)
  @test.assert_eq(c.is_expired(), true)
  @test.assert_eq(c.is_now_valid(), false)
}

// =============================================================================
//  7. HS384 / HS512
// =============================================================================

///|
test "ex07 HS384 and HS512" {
  // HS384
  let s384 = HmacSigner::new("HS384", "shared-key") catch { e => raise e }
  let v384 = HmacVerifier::new("HS384", "shared-key") catch { e => raise e }
  let t384 = @mjwt.encode_with(s384, JwtClaims::new())
  let d384 = @mjwt.decode_with(v384, t384)
  @test.assert_eq(d384.header.alg, "HS384")

  // HS512
  let s512 = HmacSigner::new("HS512", "shared-key") catch { e => raise e }
  let v512 = HmacVerifier::new("HS512", "shared-key") catch { e => raise e }
  let t512 = @mjwt.encode_with(s512, JwtClaims::new())
  let d512 = @mjwt.decode_with(v512, t512)
  @test.assert_eq(d512.header.alg, "HS512")
}

// =============================================================================
//  8. ES256 (ECDSA P-256)
// =============================================================================

///|
test "ex08 ES256 sign & verify" {
  let priv_key = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
  let pub_key = "60fd4dd4c6c4034f1c7e0083f6c5f2010442a95d0a0e4f1d32b6d54f44576453" +
    "e4d0d3b67b1e3d378ff8003f899a8bd66b2ee7e7e45fe1d574e030f2e136b791"
  let priv_bytes = BigInt::from_string(priv_key, radix=16).to_octets(length=32)
  let pub_bytes = BigInt::from_string(pub_key, radix=16).to_octets(length=64)
  let signer = EcSigner::new_p256(priv_bytes.view(), pub_bytes.view())
  let verifier = EcVerifier::new_p256(pub_bytes.view())

  let claims = JwtClaims::new()
  claims.set_subject("ecdsa-test")
  let token = @mjwt.encode_with(signer, claims)
  let decoded = @mjwt.decode_with(verifier, token)
  @test.assert_eq(decoded.header.alg, "ES256")
  @test.assert_eq(decoded.claims.get_subject(), Some("ecdsa-test"))
}

// =============================================================================
//  9. RS256 (RSA PKCS#1 v1.5)
// =============================================================================

///|
test "ex09 RS256 sign" {
  let n_hex = "ab3668be17c15c54c1f989cf75980f99f1a9c1c06e265bff1abdcb9f525bfed4636638b35b4a40b4862e41653fc4882ca520295fe890f75e8af91e44c62c5d7acc1a85c5edaf5f65115ec140cb4a667132f007ea6295cee089e1e8ae96256ff4beec64779691b0780c7fbc5c71cb068cc2b99540275f93e56cde2813ab4244abc66d80fea26e24127047f9edc1c1b2091d633e968347d452383c0a1de50d88a5c3687747c3569cdd3128015a18e791a9548139a95d245e8af658b63cc056b5d84ed5127a7486c00ff07856a25542ace9aed39a4a92346fb4711997b49e0e480706211bcbc7336afb3228382aeee12034d60997212befe4956d9267b585110385"
  let d_hex = "25248115981eb51298203402e32e715802c2c28b25fa4163f6dfacd06bf41434ec396d5c8f95ecb29d1764cd7bc77d893deb5bbe783c16c6165d13f17492845712f740051fdab755bc2e73bb443ee8396f84fe1a9d77857155c8420bb9fbf62d40cc14c192d31956f9d32e4059d9631adf559668dc01d29a67834c6b73f044e82a0fa0e4de9a3f9b41e1aa2ffb65bb07607b19a2ece782ab6d42d5c233231c4380035509b1c9fd2ad5f203b26efa0a8dfec16b978b0b523c92c92945c257895c0141e512ee93c05c9c9f766eb4864b54d5cd50bd7b7f1a7ac15f11e4243d0af44afde30a4f0535091ff29dcee316977dd2134a5f73600f92fe86e8c2477075d1"
  let n_bytes = BigInt::from_string(n_hex, radix=16).to_octets(length=256)
  let d_bytes = BigInt::from_string(d_hex, radix=16).to_octets(length=256)
  let signer = RsaSigner::new(n_bytes.view(), d_bytes.view(), "RS256") catch { e => raise e }
  let claims = JwtClaims::new()
  claims.set_subject("rsa-test")
  let token = @mjwt.encode_with(signer, claims)
  @test.assert_not_eq(token.length(), 0)
  let mut dots = 0
  for ch in token { if ch == '.' { dots = dots + 1 } }
  @test.assert_eq(dots, 2)
}

// =============================================================================
//  10. Error handling
// =============================================================================

///|
test "ex10 wrong key rejected" {
  let token = @mjwt.encode(JwtClaims::new(), "real-key")
  let _ = @test.expect_error(fn() raise {
    @mjwt.decode(token, "fake-key")
  })
}

///|
test "ex11 malformed token rejected" {
  @test.assert_eq(@mjwt.verify("not-a-jwt", "s"), false)
  @test.assert_eq(@mjwt.verify("a.b", "s"), false)
  let _ = @test.expect_error(fn() raise {
    @mjwt.decode("no-dots", "s")
  })
}

// =============================================================================
//  11. Inspect without verification (debugging / logging)
// =============================================================================

///|
test "ex12 inspect without verify" {
  let c = JwtClaims::new()
  c.set_subject("debug-user")
  let token = @mjwt.encode(c, "hidden")
  let raw = @mjwt.decode_without_verify(token)
  @test.assert_eq(raw.claims.get_subject(), Some("debug-user"))
}
