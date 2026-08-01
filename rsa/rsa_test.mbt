// Blackbox tests for the RSA (RS256) signer/verifier in this package.

///|
let rsa_n_hex = "bdd7d4fa99a5f4b2a4c3b5090abd12363e087a1885220843cfec1c0562aae4e588f3afd138d96f2444e288943673725d7bda86b4c01c0353557c6f57c55e479f54731a415daed140b163c63ab83de8ed67150795846878599cd97297b431ea3787d8c4ce21d95e1305b8fae4ada9b47ef7f09b6718d27eae1347f5329309f3b601855e3d0bdb065fe4f7dc767a728966581c5e85b45df6480ee98094a3debfddf3ca89878afd3bd6fa56b0304ed40660009c190b04d94b8774fbef5799c3c074ab8f29128c5ad4d94432e4d1be200abdd5a117de35b2c7bbaeabec48b86750adc0529bd5b3cd4edd2ea4d5ae6b0d0d917b147c49c330929c8f8315d702f6be11"

///|
let rsa_d_hex = "34c80639ea701e99707fcd1c8774cbd472e8ce7174ca627be01a282c43237a626af23da6b0e49b26fd53f25f2ac86c3a9b8dc53809d580033258576892c244ad82c041c37cb5770e42839800896b0510c4412f8b9d75a2485ff88108b69bce1fc4503b5f883fb40d1be13338532444bfac55a40f44f2793012c245e4dac6c09015ed4d5023c0f5f67a72e5c8ecb750cbcbea32c6ce425891576b0199514a849bb2a52463f5866b73ceaa5431c597597e12bd8aa578329a33b1b36bc376d705f9d026abd47feb24dc01a2ee973605fe8ddfb05255ac3049d3b39f327086cdb447d36a81124c5d3e127320c3037bd8485a856a5771b50f5cc39272e41373d49d15"

///|
let rsa_e_hex = "010001"

///|
test "RS256 sign produces 3-part token" {
  let n_bytes = BigInt::from_string(rsa_n_hex, radix=16).to_octets(length=256)
  let d_bytes = BigInt::from_string(rsa_d_hex, radix=16).to_octets(length=256)
  let signer = RsaSigner::new(n_bytes.view(), d_bytes.view(), "RS256") catch {
    e => raise e
  }
  let claims = @mjwt.JwtClaims::new()
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
test "RS256 round-trip sign + verify" {
  let n_bytes = BigInt::from_string(rsa_n_hex, radix=16).to_octets(length=256)
  let d_bytes = BigInt::from_string(rsa_d_hex, radix=16).to_octets(length=256)
  let e_bytes = BigInt::from_string(rsa_e_hex, radix=16).to_octets(length=3)
  let signer = RsaSigner::new(n_bytes.view(), d_bytes.view(), "RS256") catch {
    e => raise e
  }
  let verifier = RsaVerifier::new(n_bytes.view(), e_bytes.view(), "RS256") catch {
    e => raise e
  }
  let claims = @mjwt.JwtClaims::new()
  claims.set_subject("rsa-roundtrip")
  let token = @mjwt.encode_with(signer, claims)
  let decoded = @mjwt.decode_with(verifier, token)
  @test.assert_eq(decoded.header.alg, "RS256")
  @test.assert_eq(decoded.claims.get_subject(), Some("rsa-roundtrip"))
  // wrong signature must be rejected
  let tampered = token + "x"
  let _ = @test.expect_error(fn() raise {
    @mjwt.decode_with(verifier, tampered)
  })
}
