///|
/// Tests for mjwt — JWT library for MoonBit
///
/// This file contains **32 tests** covering:
/// - HS256/384/512 encode/decode/verify round-trips
/// - Standard and custom claims
/// - Error cases (wrong keys, malformed tokens, empty secrets)
/// - SHA-384/512 known-answer tests (NIST FIPS 180-4)
/// - HMAC RFC 4231 test vectors
/// - ECDSA (ES256) signature format
/// - RSA (RS256) signature format
/// - `is_expired()` / `is_now_valid()` time checks
/// - Key mismatch rejection
///
/// Benchmark tests are at the bottom, skipped in normal runs (`#skip`).

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
fn hex_to_bytes(s : StringView) -> FixedArray[Byte] {
  let chars = s.to_owned().to_array()
  let out = FixedArray::make(chars.length() / 2, b'\x00')
  for i = 0; i < out.length(); i = i + 1 {
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
test "SHA-384 KAT: empty" {
  let h = sha384(@encoding.encode(UTF8, "").view())
  @test.assert_eq(
    check_hash(
      h, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
    ),
    true,
  )
}

///|
test "SHA-384 KAT: abc" {
  let h = sha384(@encoding.encode(UTF8, "abc").view())
  @test.assert_eq(
    check_hash(
      h, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    ),
    true,
  )
}

///|
test "SHA-384 KAT: 112 bytes (multi-block)" {
  let input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
  // one-shot via convenience function
  let h1 = sha384(@encoding.encode(UTF8, input).view())
  // incremental via CryptoHasher API (two chunks)
  let h2 = Sha384::new()
  h2.update(
    @encoding.encode(
      UTF8,
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
    ).view(),
  )
  h2.update(
    @encoding.encode(UTF8, "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu").view(),
  )
  let buf : FixedArray[Byte] = FixedArray::make(48, b'\x00')
  h2.finalize_into(buf, offset=0)
  @test.assert_eq(
    check_hash(
      h1, "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
    ),
    true,
  )
}

///|
test "SHA-512 KAT: empty" {
  let h = sha512(@encoding.encode(UTF8, "").view())
  @test.assert_eq(
    check_hash(
      h, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    ),
    true,
  )
}

///|
test "SHA-512 KAT: abc" {
  let h = sha512(@encoding.encode(UTF8, "abc").view())
  @test.assert_eq(
    check_hash(
      h, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    ),
    true,
  )
}

///|
test "SHA-512 KAT: 112 bytes (multi-block)" {
  let input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
  // one-shot via convenience function
  let h1 = sha512(@encoding.encode(UTF8, input).view())
  // incremental via CryptoHasher API (two chunks)
  let h2 = Sha512::new()
  h2.update(
    @encoding.encode(
      UTF8,
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno",
    ).view(),
  )
  h2.update(
    @encoding.encode(UTF8, "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu").view(),
  )
  let buf : FixedArray[Byte] = FixedArray::make(64, b'\x00')
  h2.finalize_into(buf, offset=0)
  @test.assert_eq(
    check_hash(
      h1, "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
    ),
    true,
  )
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
    Sha384::new(),
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
    Sha512::new(),
    @encoding.encode(UTF8, key).view(),
    @encoding.encode(UTF8, data).view(),
  )
  @test.assert_eq(check_hash(sig, expected), true)
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
test "RS256 sign produces 3-part token" {
  let n_hex = "ab3668be17c15c54c1f989cf75980f99f1a9c1c06e265bff1abdcb9f525bfed4636638b35b4a40b4862e41653fc4882ca520295fe890f75e8af91e44c62c5d7acc1a85c5edaf5f65115ec140cb4a667132f007ea6295cee089e1e8ae96256ff4beec64779691b0780c7fbc5c71cb068cc2b99540275f93e56cde2813ab4244abc66d80fea26e24127047f9edc1c1b2091d633e968347d452383c0a1de50d88a5c3687747c3569cdd3128015a18e791a9548139a95d245e8af658b63cc056b5d84ed5127a7486c00ff07856a25542ace9aed39a4a92346fb4711997b49e0e480706211bcbc7336afb3228382aeee12034d60997212befe4956d9267b585110385"
  let d_hex = "25248115981eb51298203402e32e715802c2c28b25fa4163f6dfacd06bf41434ec396d5c8f95ecb29d1764cd7bc77d893deb5bbe783c16c6165d13f17492845712f740051fdab755bc2e73bb443ee8396f84fe1a9d77857155c8420bb9fbf62d40cc14c192d31956f9d32e4059d9631adf559668dc01d29a67834c6b73f044e82a0fa0e4de9a3f9b41e1aa2ffb65bb07607b19a2ece782ab6d42d5c233231c4380035509b1c9fd2ad5f203b26efa0a8dfec16b978b0b523c92c92945c257895c0141e512ee93c05c9c9f766eb4864b54d5cd50bd7b7f1a7ac15f11e4243d0af44afde30a4f0535091ff29dcee316977dd2134a5f73600f92fe86e8c2477075d1"
  let n_bytes = BigInt::from_string(n_hex, radix=16).to_octets(length=256)
  let d_bytes = BigInt::from_string(d_hex, radix=16).to_octets(length=256)
  let signer = RsaSigner::new(n_bytes.view(), d_bytes.view(), "RS256") catch {
    e => raise e
  }
  let claims = JwtClaims::new()
  claims.set_subject("rsa-test")
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

// =============================================================================
//  Benchmarks (skipped in normal test runs)
// =============================================================================

///|
#skip("benchmark")
test "bench encode HS256" {
  let c = JwtClaims::new()
  c.set_subject("benchmark-user")
  ignore(
    @bench.single_bench(name="encode HS256", count=10, fn() {
      ignore(@mjwt.encode(c, "my-secret-key-12345678") catch { _ => "" })
    }),
  )
}

///|
#skip("benchmark")
test "bench decode HS256" {
  let claims = JwtClaims::new()
  claims.set_subject("benchmark-user")
  let token = @mjwt.encode(claims, "my-secret-key-12345678")
  ignore(
    @bench.single_bench(name="decode HS256", count=10, fn() {
      ignore(
        @mjwt.decode(token, "my-secret-key-12345678") catch {
          _ =>
            {
              header: JwtHeader::new(""),
              claims: JwtClaims::new(),
              signature: FixedArray::make(0, b'\x00'),
            }
        },
      )
    }),
  )
}

///|
#skip("benchmark")
test "bench RS256 sign" {
  let n_hex = "ab3668be17c15c54c1f989cf75980f99f1a9c1c06e265bff1abdcb9f525bfed4636638b35b4a40b4862e41653fc4882ca520295fe890f75e8af91e44c62c5d7acc1a85c5edaf5f65115ec140cb4a667132f007ea6295cee089e1e8ae96256ff4beec64779691b0780c7fbc5c71cb068cc2b99540275f93e56cde2813ab4244abc66d80fea26e24127047f9edc1c1b2091d633e968347d452383c0a1de50d88a5c3687747c3569cdd3128015a18e791a9548139a95d245e8af658b63cc056b5d84ed5127a7486c00ff07856a25542ace9aed39a4a92346fb4711997b49e0e480706211bcbc7336afb3228382aeee12034d60997212befe4956d9267b585110385"
  let d_hex = "25248115981eb51298203402e32e715802c2c28b25fa4163f6dfacd06bf41434ec396d5c8f95ecb29d1764cd7bc77d893deb5bbe783c16c6165d13f17492845712f740051fdab755bc2e73bb443ee8396f84fe1a9d77857155c8420bb9fbf62d40cc14c192d31956f9d32e4059d9631adf559668dc01d29a67834c6b73f044e82a0fa0e4de9a3f9b41e1aa2ffb65bb07607b19a2ece782ab6d42d5c233231c4380035509b1c9fd2ad5f203b26efa0a8dfec16b978b0b523c92c92945c257895c0141e512ee93c05c9c9f766eb4864b54d5cd50bd7b7f1a7ac15f11e4243d0af44afde30a4f0535091ff29dcee316977dd2134a5f73600f92fe86e8c2477075d1"
  let n_bytes = BigInt::from_string(n_hex, radix=16).to_octets(length=256)
  let d_bytes = BigInt::from_string(d_hex, radix=16).to_octets(length=256)
  let signer = RsaSigner::new(n_bytes.view(), d_bytes.view(), "RS256") catch {
    e => raise e
  }
  let claims = JwtClaims::new()
  claims.set_subject("bench-rsa")
  ignore(
    @bench.single_bench(name="RS256 sign", count=5, fn() {
      ignore(@mjwt.encode_with(signer, claims) catch { _ => "" })
    }),
  )
}

///|
#skip("benchmark")
test "bench ES256 sign" {
  let priv_key = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
  let pub_key = "60fd4dd4c6c4034f1c7e0083f6c5f2010442a95d0a0e4f1d32b6d54f44576453" +
    "e4d0d3b67b1e3d378ff8003f899a8bd66b2ee7e7e45fe1d574e030f2e136b791"
  let priv_bytes = BigInt::from_string(priv_key, radix=16).to_octets(length=32)
  let pub_bytes = BigInt::from_string(pub_key, radix=16).to_octets(length=64)
  let signer = EcSigner::new_p256(priv_bytes.view(), pub_bytes.view())
  let claims = JwtClaims::new()
  claims.set_subject("bench-ecdsa")
  ignore(
    @bench.single_bench(name="ES256 sign", count=5, fn() {
      ignore(@mjwt.encode_with(signer, claims) catch { _ => "" })
    }),
  )
}
