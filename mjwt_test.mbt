///|
/// Tests for mjwt - JWT library for MoonBit
///

///|
/// Test basic JWT encoding and decoding
test "encode and decode HS256 token" {
  let secret = "my-secret-key"
  let claims = JwtClaims::new()
  claims.set_sub("user123")
  claims.set_iss("moonbit-app")

  let token = @mjwt.encode(HS256, claims, secret)
  @test.assert_not_eq(token.length(), 0)

  let decoded = @mjwt.decode(token, secret)
  @test.assert_eq(decoded.header.alg, HS256)
  @test.assert_eq(decoded.claims.get_sub(), Some("user123"))
  @test.assert_eq(decoded.claims.get_iss(), Some("moonbit-app"))
}

///|
/// Test JWT verification
test "verify token signature" {
  let secret = "my-secret-key"
  let claims = JwtClaims::new()
  claims.set_sub("test-user")

  let token = @mjwt.encode(HS256, claims, secret)

  @test.assert_eq(@mjwt.verify(token, secret), true)
  @test.assert_eq(@mjwt.verify(token, "wrong-key"), false)
}

///|
/// Test token with wrong secret fails
test "decode with wrong secret fails" {
  let secret = "correct-secret"
  let claims = JwtClaims::new()
  claims.set_sub("user123")

  let token = @mjwt.encode(HS256, claims, secret)
  let _ = @test.expect_error(fn () raise { @mjwt.decode(token, "wrong-secret") })
}

///|
/// Test decode without verification
test "decode without verify" {
  let secret = "my-secret-key"
  let claims = JwtClaims::new()
  claims.set_sub("test-user")
  claims.set("role", Json::string("admin"))

  let token = @mjwt.encode(HS256, claims, secret)
  let decoded = @mjwt.decode_without_verify(token)

  @test.assert_eq(decoded.claims.get_sub(), Some("test-user"))
  let role = match decoded.claims.get("role") {
    Some(String(s)) => s
    _ => ""
  }
  @test.assert_eq(role, "admin")
}

///|
/// Test standard claims
test "standard claims" {
  let claims = JwtClaims::new()
  claims.set_sub("user123")
  claims.set_iss("issuer")
  claims.set_aud("audience")
  claims.set_jti("unique-id-123")
  claims.set_iat(1700000000L)

  @test.assert_eq(claims.get_sub(), Some("user123"))
  @test.assert_eq(claims.get_iss(), Some("issuer"))
  @test.assert_eq(claims.get_aud(), Some("audience"))
  @test.assert_eq(claims.get_jti(), Some("unique-id-123"))
  @test.assert_eq(claims.get_iat(), Some(1700000000L))
}

///|
/// Test invalid token formats
test "invalid token format" {
  let _ = @test.expect_error(fn () raise { @mjwt.decode("invalid-token", "secret") })
  let _ = @test.expect_error(fn () raise { @mjwt.decode("part1.part2", "secret") })
}

///|
/// Test empty secret
test "token with empty secret" {
  let claims = JwtClaims::new()
  claims.set_sub("user")

  let token = @mjwt.encode(HS256, claims, "")
  let decoded = @mjwt.decode(token, "")
  @test.assert_eq(decoded.claims.get_sub(), Some("user"))
}

///|
/// Test token with special characters in claims
test "token with special characters" {
  let claims = JwtClaims::new()
  claims.set("name", Json::string("John Doe <john@example.com>"))
  claims.set("data", Json::object({
    let m = Map([], capacity=1)
    m.set("nested", Json::string("value with spaces"))
    m
  }))

  let token = @mjwt.encode(HS256, claims, "secret-key")
  let decoded = @mjwt.decode(token, "secret-key")

  let name = match decoded.claims.get("name") {
    Some(String(s)) => s
    _ => ""
  }
  @test.assert_eq(name, "John Doe <john@example.com>")
}

///|
/// Test token with numeric claims
test "token with numeric claims" {
  let claims = JwtClaims::new()
  claims.set_exp(2000000000L)
  claims.set_nbf(1000000000L)

  let token = @mjwt.encode(HS256, claims, "secret")
  let decoded = @mjwt.decode(token, "secret")

  @test.assert_eq(decoded.claims.get_exp(), Some(2000000000L))
  @test.assert_eq(decoded.claims.get_nbf(), Some(1000000000L))
}

///|
/// Debug: test HMAC directly
test "debug hmac" {
  let key = "key"
  let msg = "test"
  let key_bytes = @encoding.encode(UTF8, key)
  let msg_bytes = @encoding.encode(UTF8, msg)
  let sha256 = @crypto.SHA256::new()
  let sig1 = @crypto.hmac(sha256, key_bytes.view(), msg_bytes.view())
  let sha256_2 = @crypto.SHA256::new()
  let sig2 = @crypto.hmac(sha256_2, key_bytes.view(), msg_bytes.view())
  let eq = sig1.length() == sig2.length()
  @test.assert_eq(eq, true)
}
