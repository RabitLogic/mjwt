// Whitebox tests run within the package scope (core + HMAC only).
// Use them to validate internal helpers or invariants.
// Keep them focused; public behavior belongs in `_test.mbt`.
//
// RSA internal tests: `rsa/rsa_wbtest.mbt`; ECDSA internal tests:
// `ecdsa/ecdsa_wbtest.mbt`.

///|
test "base64url_encode: 1 byte (partial block)" {
  // 0x41 = 'A' → "QQ" (padding omitted)
  @test.assert_eq(base64url_encode(Bytes::make(1, b'\x41').view()), "QQ")
}

///|
test "base64url_encode: 2 bytes (partial block)" {
  // "AB" → "QUI" (padding omitted)
  let b = Bytes::from_array([b'\x41', b'\x42'])
  @test.assert_eq(base64url_encode(b.view()), "QUI")
}

///|
test "base64url_encode: 3 bytes (full block)" {
  // "ABC" → "QUJD"
  let b = Bytes::from_array([b'\x41', b'\x42', b'\x43'])
  @test.assert_eq(base64url_encode(b.view()), "QUJD")
}

///|
test "base64url round-trip decodes back" {
  let b = Bytes::from_array([b'\x00', b'\xfb', b'\xff', b'\x01', b'\x80'])
  let dec = base64url_decode(base64url_encode(b.view()))
  @test.assert_eq(dec.to_array(), b.to_array())
}

///|
test "verify still accepts correct HS256 token" {
  let claims = JwtClaims::new()
  claims.set_subject("verify-ok")
  let token = encode(claims, "secret")
  @test.assert_eq(verify(token, "secret"), true)
  @test.assert_eq(verify(token, "wrong"), false)
}

///|
test "exp/iat/nbf exact Int64 precision (>2^53)" {
  let c = JwtClaims::new()
  let big = 9_000_000_000_000_000_001L // > 2^53, not representable in Double
  c.set_expiration(big)
  c.set_not_before(big)
  c.set_issued_at(big)
  @test.assert_eq(c.get_expiration(), Some(big))
  @test.assert_eq(c.get_not_before(), Some(big))
  @test.assert_eq(c.get_issued_at(), Some(big))
  // payload must contain the exact integer text (no scientific notation)
  let payload = c.to_json().stringify()
  @test.assert_eq(payload.contains("9000000000000000001"), true)
  // full round-trip through encode/decode preserves precision
  let token = encode(c, "secret")
  let d = decode(token, "secret")
  @test.assert_eq(d.claims.get_expiration(), Some(big))
  @test.assert_eq(d.claims.get_not_before(), Some(big))
  @test.assert_eq(d.claims.get_issued_at(), Some(big))
}

///|
test "is_expired_with_leeway tolerates clock skew (RFC 7519 §4.1.4)" {
  let now_s = (@env.now() / 1000).reinterpret_as_int64()
  let c = JwtClaims::new()
  c.set_expiration(now_s - 30L) // expired 30s ago
  @test.assert_eq(c.is_expired(), true)
  @test.assert_eq(c.is_expired_with_leeway(60L), false) // leeway covers it
  @test.assert_eq(c.is_expired_with_leeway(10L), true) // leeway too small
}

///|
test "is_now_valid_with_leeway tolerates nbf in the future" {
  let now_s = (@env.now() / 1000).reinterpret_as_int64()
  let c = JwtClaims::new()
  c.set_not_before(now_s + 30L) // nbf 30s in the future
  @test.assert_eq(c.is_now_valid(), false)
  @test.assert_eq(c.is_now_valid_with_leeway(60L), true)
  @test.assert_eq(c.is_now_valid_with_leeway(10L), false)
}
