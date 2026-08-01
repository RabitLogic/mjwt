///|
/// Benchmarks for the core `mjwt` package (HS256 encode/decode).
///
/// RS256 benchmarks live in `rsa/rsa_bench_test.mbt`; ES256 benchmarks live in
/// `ecdsa/ecdsa_bench_test.mbt`.
///
/// Run with:  moon bench

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
