///|
/// Tests for the core `mjwt` package: HMAC (HS256/384/512), standard claims,
/// error handling, and the HS256 convenience API.
///
/// RSA (RS256) tests live in `rsa/rsa_test.mbt`; ECDSA (ES256) tests live in
/// `ecdsa/ecdsa_test.mbt`; SHA-384/512 KAT tests live in `hash/sha512_test.mbt`.

// =============================================================================
//  HS256 encode / decode
// =============================================================================

///|
test "HS256 round-trip" {
  let claims = JwtClaims::new()
  claims.set_subject("user123")
  claims.set_issuer("moonbit-app")
  let token = @mjwt.encode(claims, "my-secret-key")
  @test.assert_not_eq(token.length(), 0)
  let decoded = @mjwt.decode(token, "my-secret-key")
  @test.assert_eq(decoded.header.alg, "HS256")
  @test.assert_eq(decoded.claims.get_subject(), Some("user123"))
  @test.assert_eq(decoded.claims.get_issuer(), Some("moonbit-app"))
}

///|
test "verify true for correct secret" {
  let token = @mjwt.encode(JwtClaims::new(), "my-secret")
  @test.assert_eq(@mjwt.verify(token, "my-secret"), true)
  @test.assert_eq(@mjwt.verify(token, "wrong-secret"), false)
}

///|
test "verify false for malformed token" {
  @test.assert_eq(@mjwt.verify("not-a-jwt", "secret"), false)
  @test.assert_eq(@mjwt.verify("a.b", "secret"), false)
}

///|
test "decode with wrong secret fails" {
  let token = @mjwt.encode(JwtClaims::new(), "correct-secret")
  let _ = @test.expect_error(fn() raise { @mjwt.decode(token, "wrong-secret") })
}

///|
test "decode without verify yields claims" {
  let c = JwtClaims::new()
  c.set_subject("test-user")
  c.set("role", Json::string("admin"))
  let d = @mjwt.decode_without_verify(@mjwt.encode(c, "ignored"))
  @test.assert_eq(d.claims.get_subject(), Some("test-user"))
  match d.claims.get("role") {
    Some(String(s)) => @test.assert_eq(s, "admin")
    _ => @test.fail("")
  }
}

// =============================================================================
//  Standard claims
// =============================================================================

///|
test "standard claims" {
  let c = JwtClaims::new()
  c.set_subject("sub")
  c.set_issuer("iss")
  c.set_audience("aud")
  c.set_jwt_id("jti")
  c.set_issued_at(1_700_000_000L)
  c.set_expiration(1_800_000_000L)
  c.set_not_before(1_600_000_000L)
  @test.assert_eq(c.get_subject(), Some("sub"))
  @test.assert_eq(c.get_issuer(), Some("iss"))
  @test.assert_eq(c.get_audience(), Some("aud"))
  @test.assert_eq(c.get_jwt_id(), Some("jti"))
  @test.assert_eq(c.get_issued_at(), Some(1_700_000_000L))
  @test.assert_eq(c.get_expiration(), Some(1_800_000_000L))
  @test.assert_eq(c.get_not_before(), Some(1_600_000_000L))
}

///|
test "aud supports string-or-array (RFC 7519 §4.1.3)" {
  let c = JwtClaims::new()
  // single audience -> JSON string
  c.set_audience("api")
  @test.assert_eq(c.get_audience(), Some("api"))
  match c.get_audiences() {
    Some(a) => {
      @test.assert_eq(a.length(), 1)
      @test.assert_eq(a[0], "api")
    }
    _ => @test.fail("")
  }
  // multiple audiences -> JSON array
  c.set_audiences(["api", "web"])
  @test.assert_eq(c.get_audience(), None) // array form is not a plain string
  match c.get_audiences() {
    Some(a) => {
      @test.assert_eq(a.length(), 2)
      @test.assert_eq(a[0], "api")
      @test.assert_eq(a[1], "web")
    }
    _ => @test.fail("")
  }
  // round-trips through encode/decode
  let d = @mjwt.decode(@mjwt.encode(c, "secret"), "secret")
  match d.claims.get_audiences() {
    Some(a) => {
      @test.assert_eq(a.length(), 2)
      @test.assert_eq(a[0], "api")
      @test.assert_eq(a[1], "web")
    }
    _ => @test.fail("")
  }
}

///|
test "is_expired returns false when absent" {
  let c = JwtClaims::new()
  @test.assert_eq(c.is_expired(), false)
  @test.assert_eq(c.is_now_valid(), true)
}

///|
test "is_expired returns true for past timestamp" {
  let c = JwtClaims::new()
  c.set_expiration(1_000_000_000L)
  @test.assert_eq(c.is_expired(), true)
  @test.assert_eq(c.is_now_valid(), false)
}

///|
test "is_expired returns false for future timestamp" {
  let c = JwtClaims::new()
  c.set_expiration(9_999_999_999L)
  @test.assert_eq(c.is_expired(), false)
  @test.assert_eq(c.is_now_valid(), true)
}

///|
test "is_now_valid checks both nbf and exp" {
  let c = JwtClaims::new()
  c.set_expiration(9_999_999_999L)
  c.set_not_before(1_000_000_000L)
  @test.assert_eq(c.is_now_valid(), true)
  c.set_not_before(9_999_999_998L)
  @test.assert_eq(c.is_now_valid(), false)
}

// =============================================================================
//  Error handling
// =============================================================================

///|
test "malformed tokens rejected" {
  let _ = @test.expect_error(fn() raise { @mjwt.decode("no-dots", "s") })
  let _ = @test.expect_error(fn() raise { @mjwt.decode("a.b", "s") })
}

///|
test "token with empty secret" {
  let _ = @mjwt.decode(@mjwt.encode(JwtClaims::new(), ""), "")
}

///|
test "token with special characters" {
  let c = JwtClaims::new()
  c.set("name", Json::string("John <john@example.com>"))
  let d = @mjwt.decode(@mjwt.encode(c, "key"), "key")
  match d.claims.get("name") {
    Some(String(s)) => @test.assert_eq(s, "John <john@example.com>")
    _ => @test.fail("")
  }
}

///|
test "token with numeric claims" {
  let c = JwtClaims::new()
  c.set_expiration(2_000_000_000L)
  c.set_not_before(1_000_000_000L)
  let d = @mjwt.decode(@mjwt.encode(c, "secret"), "secret")
  @test.assert_eq(d.claims.get_expiration(), Some(2_000_000_000L))
  @test.assert_eq(d.claims.get_not_before(), Some(1_000_000_000L))
}

// =============================================================================
//  Trait-based encode_with / decode_with
// =============================================================================

///|
test "encode_with / decode_with" {
  let s = HmacSigner::new("HS256", "my-key")
  let v = HmacVerifier::new("HS256", "my-key")
  let c = JwtClaims::new()
  c.set_subject("trait-test")
  let t = @mjwt.encode_with(s, c)
  let d = @mjwt.decode_with(v, t)
  @test.assert_eq(d.claims.get_subject(), Some("trait-test"))
  @test.assert_eq(d.header.alg, "HS256")
}

///|
test "encode_with / decode_with key mismatch fails" {
  let v = HmacVerifier::new("HS256", "wrong-key")
  let _ = @test.expect_error(fn() raise {
    @mjwt.decode_with(
      v,
      @mjwt.encode_with(HmacSigner::new("HS256", "real-key"), JwtClaims::new()),
    )
  })
}

// =============================================================================
//  HMAC RFC 4231 test vectors (HS384/HS512 use @mjwt/hash hashers)
// =============================================================================

///|
fn hex_to_bytes(s : StringView) -> FixedArray[Byte] {
  let chars = s.to_owned().to_array()
  let out = FixedArray::make(s.length() / 2, b'\x00')
  for i = 0; i < s.length() / 2; i = i + 1 {
    let hi = match chars[i * 2] {
      '0'..='9' => chars[i * 2].to_int() - '0'
      'a'..='f' => chars[i * 2].to_int() - 'a' + 10
      'A'..='F' => chars[i * 2].to_int() - 'A' + 10
      _ => 0
    }
    let lo = match chars[i * 2 + 1] {
      '0'..='9' => chars[i * 2 + 1].to_int() - '0'
      'a'..='f' => chars[i * 2 + 1].to_int() - 'a' + 10
      'A'..='F' => chars[i * 2 + 1].to_int() - 'A' + 10
      _ => 0
    }
    out[i] = (hi * 16 + lo).to_byte()
  }
  out
}

///|
fn check_hash(h : FixedArray[Byte], expected_hex : StringView) -> Bool {
  let expected = hex_to_bytes(expected_hex)
  if h.length() != expected.length() {
    return false
  }
  for i = 0; i < h.length(); i = i + 1 {
    if h[i] != expected[i] {
      return false
    }
  }
  true
}

///|
test "HMAC-SHA256 RFC 4231 Test Case 2" {
  let key = "Jefe"
  let data = "what do ya want for nothing?"
  let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
  let sig = @crypto.hmac(
    @crypto.SHA256::new(),
    @encoding.encode(UTF8, key).view(),
    @encoding.encode(UTF8, data).view(),
  )
  @test.assert_eq(check_hash(sig, expected), true)
}

///|
test "HMAC-SHA384 RFC 4231 Test Case 2" {
  let key = "Jefe"
  let data = "what do ya want for nothing?"
  let expected = "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"
  let sig = @crypto.hmac(
    @hash.Sha384::new(),
    @encoding.encode(UTF8, key).view(),
    @encoding.encode(UTF8, data).view(),
  )
  @test.assert_eq(check_hash(sig, expected), true)
}

///|
test "HMAC-SHA512 RFC 4231 Test Case 2" {
  let key = "Jefe"
  let data = "what do ya want for nothing?"
  let expected = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
  let sig = @crypto.hmac(
    @hash.Sha512::new(),
    @encoding.encode(UTF8, key).view(),
    @encoding.encode(UTF8, data).view(),
  )
  @test.assert_eq(check_hash(sig, expected), true)
}

// =============================================================================
//  HS384 / HS512 round-trips
// =============================================================================

///|
test "HS384 round-trip" {
  let s = HmacSigner::new("HS384", "shared-secret")
  let v = HmacVerifier::new("HS384", "shared-secret")
  let c = JwtClaims::new()
  c.set_subject("hs384-test")
  let d = @mjwt.decode_with(v, @mjwt.encode_with(s, c))
  @test.assert_eq(d.header.alg, "HS384")
  @test.assert_eq(d.claims.get_subject(), Some("hs384-test"))
}

///|
test "HS384 wrong key fails" {
  let s = HmacSigner::new("HS384", "real-key")
  let v = HmacVerifier::new("HS384", "fake-key")
  let _ = @test.expect_error(fn() raise {
    @mjwt.decode_with(v, @mjwt.encode_with(s, JwtClaims::new()))
  })
}

///|
test "HS512 round-trip" {
  let s = HmacSigner::new("HS512", "shared-secret")
  let v = HmacVerifier::new("HS512", "shared-secret")
  let c = JwtClaims::new()
  c.set_subject("hs512-test")
  let d = @mjwt.decode_with(v, @mjwt.encode_with(s, c))
  @test.assert_eq(d.header.alg, "HS512")
  @test.assert_eq(d.claims.get_subject(), Some("hs512-test"))
}

///|
test "HS512 wrong key fails" {
  let s = HmacSigner::new("HS512", "real-key")
  let v = HmacVerifier::new("HS512", "fake-key")
  let _ = @test.expect_error(fn() raise {
    @mjwt.decode_with(v, @mjwt.encode_with(s, JwtClaims::new()))
  })
}
