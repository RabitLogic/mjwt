// Whitebox tests for internal RSA helpers (blinding, min key size, alg-mismatch
// rejection, and the core `from_octets` zero-bug workaround).

///|
let wbt_rsa_n_hex = "bdd7d4fa99a5f4b2a4c3b5090abd12363e087a1885220843cfec1c0562aae4e588f3afd138d96f2444e288943673725d7bda86b4c01c0353557c6f57c55e479f54731a415daed140b163c63ab83de8ed67150795846878599cd97297b431ea3787d8c4ce21d95e1305b8fae4ada9b47ef7f09b6718d27eae1347f5329309f3b601855e3d0bdb065fe4f7dc767a728966581c5e85b45df6480ee98094a3debfddf3ca89878afd3bd6fa56b0304ed40660009c190b04d94b8774fbef5799c3c074ab8f29128c5ad4d94432e4d1be200abdd5a117de35b2c7bbaeabec48b86750adc0529bd5b3cd4edd2ea4d5ae6b0d0d917b147c49c330929c8f8315d702f6be11"

///|
let wbt_rsa_d_hex = "34c80639ea701e99707fcd1c8774cbd472e8ce7174ca627be01a282c43237a626af23da6b0e49b26fd53f25f2ac86c3a9b8dc53809d580033258576892c244ad82c041c37cb5770e42839800896b0510c4412f8b9d75a2485ff88108b69bce1fc4503b5f883fb40d1be13338532444bfac55a40f44f2793012c245e4dac6c09015ed4d5023c0f5f67a72e5c8ecb750cbcbea32c6ce425891576b0199514a849bb2a52463f5866b73ceaa5431c597597e12bd8aa578329a33b1b36bc376d705f9d026abd47feb24dc01a2ee973605fe8ddfb05255ac3049d3b39f327086cdb447d36a81124c5d3e127320c3037bd8485a856a5771b50f5cc39272e41373d49d15"

///|
test "RSA blinding preserves the deterministic signature" {
  // RSA PKCS#1 v1.5 signatures are deterministic (s = m^d mod n). Blinding
  // must unblind back to that exact value, so two signs of the same token
  // must be byte-identical.
  let n_bytes = BigInt::from_string(wbt_rsa_n_hex, radix=16).to_octets(
    length=256,
  )
  let d_bytes = BigInt::from_string(wbt_rsa_d_hex, radix=16).to_octets(
    length=256,
  )
  let signer = RsaSigner::new(n_bytes.view(), d_bytes.view(), "RS256") catch {
    e => raise e
  }
  let claims = @mjwt.JwtClaims::new()
  claims.set_subject("blinding-check")
  let t1 = @mjwt.encode_with(signer, claims)
  let t2 = @mjwt.encode_with(signer, claims)
  @test.assert_eq(t1, t2)
}

///|
test "RsaVerifier rejects a short modulus at construction" {
  let n_short = Bytes::make(64, b'\xff') // 512-bit modulus
  let e = Bytes::from_array([b'\x01', b'\x00', b'\x01'])
  let _ = @test.expect_error(fn() raise {
    RsaVerifier::new(n_short.view(), e.view(), "RS256")
  })
}

///|
test "decode_with rejects header alg mismatch (no downgrade)" {
  // A token whose header claims an algorithm different from the verifier's
  // must be rejected before signature verification (RFC 7515 §4.1.1) — this
  // prevents algorithm-confusion / downgrade attacks.
  let claims = @mjwt.JwtClaims::new()
  claims.set_subject("alg-confusion")
  let token = @mjwt.encode(claims, "secret") // header alg = HS256
  let v = RsaVerifier::new(
    @bigint.BigInt::from_string(
      "ab3668be17c15c54c1f989cf75980f99f1a9c1c06e265bff1abdcb9f525bfed4636638b35b4a40b4862e41653fc4882ca520295fe890f75e8af91e44c62c5d7acc1a85c5edaf5f65115ec140cb4a667132f007ea6295cee089e1e8ae96256ff4beec64779691b0780c7fbc5c71cb068cc2b99540275f93e56cde2813ab4244abc66d80fea26e24127047f9edc1c1b2091d633e968347d452383c0a1de50d88a5c3687747c3569cdd3128015a18e791a9548139a95d245e8af658b63cc056b5d84ed5127a7486c00ff07856a25542ace9aed39a4a92346fb4711997b49e0e480706211bcbc7336afb3228382aeee12034d60997212befe4956d9267b585110385",
      radix=16,
    ).to_octets(length=256),
    @bigint.BigInt::from_string("010001", radix=16).to_octets(length=3),
    "RS256",
  )
  let _ = @test.expect_error(fn() raise { @mjwt.decode_with(v, token) })
}

///|
test "core-bug workaround: all-zero bytes -> canonical 0N" {
  // Regression for the MoonBit `BigInt::from_octets` zero bug. Without the
  // `bi_from_octets` workaround these crash (to_string) or fail (== / <).
  let zero = Bytes::make(32, b'\x00')
  let rz = unsigned_bigint_from_bytes(zero.view())
  @test.assert_eq(rz == 0N, true)
  @test.assert_eq(rz.to_string(), "0")
}
