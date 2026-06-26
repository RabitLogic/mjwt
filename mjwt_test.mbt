///|
/// Tests for mjwt — JWT library for MoonBit

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

///|
test "SHA-384 known-answer" {
  let h = sha384(@encoding.encode(UTF8, "abc").view())
  @test.assert_eq(h.length(), 48)
  @test.assert_eq(h[0], b'\xcb')
  @test.assert_eq(h[1], b'\x00')
}

///|
test "SHA-512 known-answer" {
  let h = sha512(@encoding.encode(UTF8, "abc").view())
  @test.assert_eq(h.length(), 64)
  @test.assert_eq(h[0], b'\xdd')
  @test.assert_eq(h[1], b'\xaf')
}

///|
test "HMAC-SHA384 deterministic" {
  let k = @encoding.encode(UTF8, "key").view()
  let m = @encoding.encode(UTF8, "msg").view()
  let a = @crypto.hmac(Sha384::new(), k, m)
  let b = @crypto.hmac(Sha384::new(), k, m)
  let mut ok = a.length() == b.length()
  for i = 0; i < a.length(); i = i + 1 {
    if a[i] != b[i] {
      ok = false
    }
  }
  @test.assert_eq(ok, true)
}

///|
test "Sha384 fresh & reset" {
  let d = @encoding.encode(UTF8, "test data").view()
  let h1 = Sha384::new()
  h1.update(d)
  let b1 : FixedArray[Byte] = FixedArray::make(48, b'\x00')
  h1.finalize_into(b1, offset=0)
  let h2 = Sha384::new()
  h2.update(d)
  let b2 : FixedArray[Byte] = FixedArray::make(48, b'\x00')
  h2.finalize_into(b2, offset=0)
  let mut ok = true
  for i = 0; i < 48; i = i + 1 {
    if b1[i] != b2[i] {
      ok = false
    }
  }
  @test.assert_eq(ok, true)
  h2.reset()
  h2.update(d)
  let b3 : FixedArray[Byte] = FixedArray::make(48, b'\x00')
  h2.finalize_into(b3, offset=0)
  let mut ok2 = true
  for i = 0; i < 48; i = i + 1 {
    if b1[i] != b3[i] {
      ok2 = false
    }
  }
  @test.assert_eq(ok2, true)
}

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

///|
test "ES256 sign only" {
  let priv_key = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
  let pub_key = "60fd4dd4c6c4034f1c7e0083f6c5f2010442a95d0a0e4f1d32b6d54f44576453" +
    "e4d0d3b67b1e3d378ff8003f899a8bd66b2ee7e7e45fe1d574e030f2e136b791"
  let priv_bytes = BigInt::from_string(priv_key, radix=16).to_octets(length=32)
  let pub_bytes = BigInt::from_string(pub_key, radix=16).to_octets(length=64)
  let signer = EcSigner::new_p256(priv_bytes.view(), pub_bytes.view())
  let claims = JwtClaims::new()
  claims.set_subject("ecdsa-test")
  let token = @mjwt.encode_with(signer, claims)
  @test.assert_not_eq(token.length(), 0)
  let mut dots = 0
  for ch in token {
    if ch == '.' {
      dots = dots + 1
    }
  }
  @test.assert_eq(dots, 2)
}
