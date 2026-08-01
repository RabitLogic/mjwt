// Blackbox tests for the ECDSA (ES256) signer/verifier in this package.

///|
let ec_priv_hex = "f5a10e3be8aa44f377955a55a8998b282437886a65078f1125b715907f7f6a7b"

///|
let ec_pub_hex = "cbba22aa20546bdfc2c4bda6786eef83e335206aa1cd57cb94501c3ce4778dc01884a2dd566365464366148f69ec76bacbf1530c95cc81fc766746f8145637d0"

///|
test "ES256 sign produces a 3-part token" {
  let priv_bytes = BigInt::from_string(ec_priv_hex, radix=16).to_octets(
    length=32,
  )
  let pub_bytes = BigInt::from_string(ec_pub_hex, radix=16).to_octets(length=64)
  let signer = EcSigner::new_p256(priv_bytes.view(), pub_bytes.view())
  let claims = @mjwt.JwtClaims::new()
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

///|
test "ES256 round-trip sign + verify" {
  let priv_bytes = BigInt::from_string(ec_priv_hex, radix=16).to_octets(
    length=32,
  )
  let pub_bytes = BigInt::from_string(ec_pub_hex, radix=16).to_octets(length=64)
  let signer = EcSigner::new_p256(priv_bytes.view(), pub_bytes.view())
  let verifier = EcVerifier::new_p256(pub_bytes.view())
  let claims = @mjwt.JwtClaims::new()
  claims.set_subject("ecdsa-roundtrip")
  let token = @mjwt.encode_with(signer, claims)
  let decoded = @mjwt.decode_with(verifier, token)
  @test.assert_eq(decoded.header.alg, "ES256")
  @test.assert_eq(decoded.claims.get_subject(), Some("ecdsa-roundtrip"))
  // wrong signature must be rejected
  let tampered = token + "x"
  let _ = @test.expect_error(fn() raise {
    @mjwt.decode_with(verifier, tampered)
  })
}
