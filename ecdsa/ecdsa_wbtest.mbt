// Whitebox tests for the internal ECDSA helpers (RFC 6979, point arithmetic,
// low-S, core `from_octets` zero-bug workaround).

///|
let wbt_ec_priv_hex = "f5a10e3be8aa44f377955a55a8998b282437886a65078f1125b715907f7f6a7b"

///|
let wbt_ec_pub_hex = "cbba22aa20546bdfc2c4bda6786eef83e335206aa1cd57cb94501c3ce4778dc01884a2dd566365464366148f69ec76bacbf1530c95cc81fc766746f8145637d0"

///|
test "RFC 6979 P-256 k vector (A.2.5)" {
  let x = BigInt::from_string(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
    radix=16,
  )
  // message "sample"
  let h1 = @crypto.sha256(
    Bytes::from_array([b's', b'a', b'm', b'p', b'l', b'e']).view(),
  )
  let z = bi_from_octets(h1.unsafe_reinterpret_as_bytes().view(), signum=1)
  let k_sample = gen_k(z, x)
  let expected = BigInt::from_string(
    "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60",
    radix=16,
  )
  @test.assert_eq(k_sample, expected)
  // message "test"
  let h2 = @crypto.sha256(Bytes::from_array([b't', b'e', b's', b't']).view())
  let z2 = bi_from_octets(h2.unsafe_reinterpret_as_bytes().view(), signum=1)
  let k_test = gen_k(z2, x)
  let expected2 = BigInt::from_string(
    "d16b6ae827f17175e040871a1c7ec3500192c4c92677336ec2537acaee0008e0",
    radix=16,
  )
  @test.assert_eq(k_test, expected2)
}

///|
test "point_on_curve accepts G, rejects off-curve points" {
  @test.assert_eq(point_on_curve(bi_gx, bi_gy), true)
  @test.assert_eq(point_on_curve(0N, 0N), false)
  @test.assert_eq(point_on_curve(bi_gx, 1N), false)
}

///|
test "ES256 produces low-S signatures and rejects high-S on verify" {
  let priv_bytes = BigInt::from_string(wbt_ec_priv_hex, radix=16).to_octets(
    length=32,
  )
  let pub_bytes = BigInt::from_string(wbt_ec_pub_hex, radix=16).to_octets(
    length=64,
  )
  let d = Scalar256::from_bytes(priv_bytes.view())
  let qx = Scalar256::from_bytes(pub_bytes[:32])
  let qy = Scalar256::from_bytes(pub_bytes[32:])
  let hash = @crypto.sha256(
    Bytes::from_array([
      b'l', b'o', b'w', b'-', b's', b'-', b'c', b'h', b'e', b'c', b'k',
    ]).view(),
  )
  let z = Scalar256::from_bytes(hash.unsafe_reinterpret_as_bytes().view())

  let (r, s) = ecdsa_sign(z, d)
  let sb = s_to_bi(s)
  // low-S: s must be in [1, n/2]
  @test.assert_eq(sb >= 1N, true)
  @test.assert_eq(sb <= bi_n_half, true)
  // the low-S signature must still verify
  @test.assert_eq(ecdsa_verify(z, qx, qy, r, s), true)
  // the high-S twin (n - s) must be rejected by the low-S check
  let high_s = bi_to_s(bi_n - sb)
  @test.assert_eq(ecdsa_verify(z, qx, qy, r, high_s), false)
}

///|
test "EcSigner rejects an off-curve public point" {
  let priv_bytes = BigInt::from_string(wbt_ec_priv_hex, radix=16).to_octets(
    length=32,
  )
  // valid x, but y forced to 1 -> not on the curve
  let bad_pub = Bytes::makei(64, fn(i) {
    if i == 32 {
      b'\x01'
    } else {
      b'\x00'
    }
  })
  let _ = @test.expect_error(fn() raise {
    EcSigner::new_p256(priv_bytes.view(), bad_pub.view())
  })
}

///|
test "core-bug workaround: all-zero bytes -> canonical 0N" {
  // Regression for the MoonBit `BigInt::from_octets` zero bug. Without the
  // `bi_from_octets` workaround these crash (to_string) or fail (== / <).
  let zero = Bytes::make(32, b'\x00')
  let z = bi_from_octets(zero.view())
  @test.assert_eq(z == 0N, true)
  @test.assert_eq(z.to_string(), "0")
  // scalar path
  let s0 = s_to_bi(Scalar256::from_bytes(Bytes::make(32, b'\x00').view()))
  @test.assert_eq(s0 == 0N, true)
  @test.assert_eq(s0.to_string(), "0")
}

///|
test "core-bug workaround: r=0 / s=0 signatures are rejected up front" {
  let priv_bytes = BigInt::from_string(wbt_ec_priv_hex, radix=16).to_octets(
    length=32,
  )
  let pub_bytes = BigInt::from_string(wbt_ec_pub_hex, radix=16).to_octets(
    length=64,
  )
  let qx = Scalar256::from_bytes(pub_bytes[:32])
  let qy = Scalar256::from_bytes(pub_bytes[32:])
  let hash = @crypto.sha256(
    Bytes::from_array([b'z', b'e', b'r', b'o', b'-', b's', b'i', b'g']).view(),
  )
  let z = Scalar256::from_bytes(hash.unsafe_reinterpret_as_bytes().view())
  let r_zero = Scalar256::from_bytes(Bytes::make(32, b'\x00').view())
  let s_zero = Scalar256::from_bytes(Bytes::make(32, b'\x00').view())
  // (r=0, s=0) must be rejected before any point math runs.
  @test.assert_eq(ecdsa_verify(z, qx, qy, r_zero, s_zero), false)
  // A valid (r, s) with one component forced to zero must also be rejected.
  let d = Scalar256::from_bytes(priv_bytes.view())
  let (r1, s1) = ecdsa_sign(z, d)
  @test.assert_eq(ecdsa_verify(z, qx, qy, r1, s_zero), false)
  @test.assert_eq(ecdsa_verify(z, qx, qy, r_zero, s1), false)
}
