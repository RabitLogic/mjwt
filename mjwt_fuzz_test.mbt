///|
/// Robustness / adversarial-input tests for the core `mjwt` package
/// (stand-in for fuzzing — MoonBit's current toolchain has no `moon fuzz`).
/// Every malformed input must be rejected with a clean `JwtError` (or `false`
/// from `verify`) and MUST NOT panic/abort, even on arbitrarily malformed or
/// huge tokens.
///
/// RSA/ECDSA robustness tests live in `rsa/` and `ecdsa/` packages.
/// These use a fixed-seed ChaCha8 RNG so failures are reproducible.

///|
let fuzz_charset : String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_./=+{}@#$%&*!~"

///|
fn random_garbage(rand : @random.Rand, max_len : Int) -> String {
  let len = rand.int(limit=max_len)
  let sb = StringBuilder::new()
  for i = 0; i < len; i = i + 1 {
    sb.write_char(
      fuzz_charset[rand.int(limit=fuzz_charset.length())]
      .to_int()
      .unsafe_to_char(),
    )
  }
  sb.to_string()
}

///|
test "fuzz: random garbage is rejected without panicking" {
  let rand = @random.Rand::chacha8(seed=b"0123456789abcdef0123456789abcdef")
  for trial = 0; trial < 500; trial = trial + 1 {
    let token = random_garbage(rand, 200)
    // verify must return false (never panic)
    @test.assert_eq(@mjwt.verify(token, "secret"), false)
    // decode / decode_without_verify must raise a JwtError, not abort
    let _ = @test.expect_error(fn() raise { @mjwt.decode(token, "secret") })
    let _ = @test.expect_error(fn() raise { @mjwt.decode_without_verify(token) })
  }
}

///|
test "fuzz: structured malformed tokens are rejected" {
  let bad_tokens = [
    "", ".", "..", "...", "a.b", "a.b.c.d", "a.b.c.d.e", "hello", ".b.c", "a..c",
    "a.b.", "%%%.%%%.%%%",
  ]
  for token in bad_tokens {
    @test.assert_eq(@mjwt.verify(token, "secret"), false)
    let _ = @test.expect_error(fn() raise { @mjwt.decode(token, "secret") })
    let _ = @test.expect_error(fn() raise { @mjwt.decode_without_verify(token) })
  }
}

///|
test "fuzz: random payload bytes inside a valid header are rejected" {
  let rand = @random.Rand::chacha8(seed=b"fedcba9876543210fedcba9876543210")
  for trial = 0; trial < 300; trial = trial + 1 {
    // valid base64url header, then random payload, then random signature
    let token = "eyJhbGciOiJIUzI1NiJ9." +
      random_garbage(rand, 120) +
      "." +
      random_garbage(rand, 120)
    @test.assert_eq(@mjwt.verify(token, "secret"), false)
    let _ = @test.expect_error(fn() raise { @mjwt.decode(token, "secret") })
  }
}

///|
test "fuzz: huge token (8 KiB of garbage) is rejected without panic" {
  let rand = @random.Rand::chacha8(seed=b"abcdef0123456789abcdef0123456789")
  let token = random_garbage(rand, 8192)
  @test.assert_eq(@mjwt.verify(token, "secret"), false)
  let _ = @test.expect_error(fn() raise { @mjwt.decode(token, "secret") })
}

///|
test "fuzz: any single-byte corruption of a valid token is rejected" {
  let claims = JwtClaims::new()
  claims.set_subject("corruption-target")
  let token = @mjwt.encode(claims, "secret")
  let len = token.length()
  // mutate one char at each position
  for i = 0; i < len; i = i + 1 {
    let ci = token[i].to_int().unsafe_to_char()
    let replacement = if ci == 'A' { 'B' } else { 'A' }
    let sb = StringBuilder::new()
    for j = 0; j < len; j = j + 1 {
      if j == i {
        sb.write_char(replacement)
      } else {
        sb.write_char(token[j].to_int().unsafe_to_char())
      }
    }
    @test.assert_eq(@mjwt.verify(sb.to_string(), "secret"), false)
  }
}
