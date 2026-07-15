///|
/// Benchmarks for mjwt — JWT library for MoonBit
///
/// Run with:  moon bench
///
/// These benchmarks use the `@bench.T` API. They run during `moon bench`
/// and are skipped during normal `moon test` runs.

// =============================================================================
//  HS256 encode / decode
// =============================================================================

///|
test "bench encode HS256" (it : @bench.T) {
  let claims = {
    let c = JwtClaims::new()
    c.set_subject("benchmark-user")
    c
  }
  it.bench(fn() {
    it.keep(@mjwt.encode(claims, "my-secret-key-12345678") catch { _ => "" })
  })
}

///|
test "bench decode HS256" (it : @bench.T) {
  let claims = {
    let c = JwtClaims::new()
    c.set_subject("benchmark-user")
    c
  }
  let token = @mjwt.encode(claims, "my-secret-key-12345678")
  it.bench(fn() {
    it.keep(
      @mjwt.decode(token, "my-secret-key-12345678") catch {
        _ =>
          {
            header: JwtHeader::new(""),
            claims: JwtClaims::new(),
            signature: FixedArray::make(0, b'\x00'),
          }
      },
    )
  })
}

// =============================================================================
//  RS256 sign
// =============================================================================

///|
test "bench RS256 sign" (it : @bench.T) {
  let n_hex = "ab3668be17c15c54c1f989cf75980f99f1a9c1c06e265bff1abdcb9f525bfed4636638b35b4a40b4862e41653fc4882ca520295fe890f75e8af91e44c62c5d7acc1a85c5edaf5f65115ec140cb4a667132f007ea6295cee089e1e8ae96256ff4beec64779691b0780c7fbc5c71cb068cc2b99540275f93e56cde2813ab4244abc66d80fea26e24127047f9edc1c1b2091d633e968347d452383c0a1de50d88a5c3687747c3569cdd3128015a18e791a9548139a95d245e8af658b63cc056b5d84ed5127a7486c00ff07856a25542ace9aed39a4a92346fb4711997b49e0e480706211bcbc7336afb3228382aeee12034d60997212befe4956d9267b585110385"
  let d_hex = "25248115981eb51298203402e32e715802c2c28b25fa4163f6dfacd06bf41434ec396d5c8f95ecb29d1764cd7bc77d893deb5bbe783c16c6165d13f17492845712f740051fdab755bc2e73bb443ee8396f84fe1a9d77857155c8420bb9fbf62d40cc14c192d31956f9d32e4059d9631adf559668dc01d29a67834c6b73f044e82a0fa0e4de9a3f9b41e1aa2ffb65bb07607b19a2ece782ab6d42d5c233231c4380035509b1c9fd2ad5f203b26efa0a8dfec16b978b0b523c92c92945c257895c0141e512ee93c05c9c9f766eb4864b54d5cd50bd7b7f1a7ac15f11e4243d0af44afde30a4f0535091ff29dcee316977dd2134a5f73600f92fe86e8c2477075d1"
  let n_bytes = BigInt::from_string(n_hex, radix=16).to_octets(length=256)
  let d_bytes = BigInt::from_string(d_hex, radix=16).to_octets(length=256)
  let signer = RsaSigner::new(n_bytes.view(), d_bytes.view(), "RS256") catch {
    e => raise e
  }
  let claims = {
    let c = JwtClaims::new()
    c.set_subject("bench-rsa")
    c
  }
  it.bench(fn() { it.keep(@mjwt.encode_with(signer, claims) catch { _ => "" }) })
}

// =============================================================================
//  ES256 sign
// =============================================================================

///|
test "bench ES256 sign (current impl)" (it : @bench.T) {
  let priv_key = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
  let pub_key = "60fd4dd4c6c4034f1c7e0083f6c5f2010442a95d0a0e4f1d32b6d54f44576453" +
    "e4d0d3b67b1e3d378ff8003f899a8bd66b2ee7e7e45fe1d574e030f2e136b791"
  let priv_bytes = BigInt::from_string(priv_key, radix=16).to_octets(length=32)
  let pub_bytes = BigInt::from_string(pub_key, radix=16).to_octets(length=64)
  let signer = EcSigner::new_p256(priv_bytes.view(), pub_bytes.view())
  let claims = {
    let c = JwtClaims::new()
    c.set_subject("bench-ecdsa")
    c
  }
  it.bench(fn() { it.keep(@mjwt.encode_with(signer, claims) catch { _ => "" }) })
}

// Note: For comparison with Tigls/mb-p256, add the dependency and uncomment:
//   moon add Tigls/mb-p256
// Then use @Tigls.mb_p256.ecdsa_sign_bytes(priv_bytes, message)
