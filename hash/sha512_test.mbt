// Blackbox tests for the SHA-384 / SHA-512 implementation (FIPS 180-4).
// These verify against NIST known-answer test vectors.

///|
fn hex_to_bytes(s : StringView) -> FixedArray[Byte] {
  let chars = s
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
