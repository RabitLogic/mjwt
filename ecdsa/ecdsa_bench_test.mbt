///|
/// Benchmarks for the ECDSA (ES256) signer/verifier.
///
/// Run with:  moon bench

///|
let bench_ec_priv = "f5a10e3be8aa44f377955a55a8998b282437886a65078f1125b715907f7f6a7b"

///|
let bench_ec_pub = "cbba22aa20546bdfc2c4bda6786eef83e335206aa1cd57cb94501c3ce4778dc01884a2dd566365464366148f69ec76bacbf1530c95cc81fc766746f8145637d0"

///|
test "bench ES256 sign" (it : @bench.T) {
  let priv_bytes = BigInt::from_string(bench_ec_priv, radix=16).to_octets(
    length=32,
  )
  let pub_bytes = BigInt::from_string(bench_ec_pub, radix=16).to_octets(
    length=64,
  )
  let signer = EcSigner::new_p256(priv_bytes.view(), pub_bytes.view())
  let claims = {
    let c = @mjwt.JwtClaims::new()
    c.set_subject("bench-ecdsa")
    c
  }
  it.bench(fn() { it.keep(@mjwt.encode_with(signer, claims) catch { _ => "" }) })
}

///|
test "bench ES256 verify" (it : @bench.T) {
  let priv_bytes = BigInt::from_string(bench_ec_priv, radix=16).to_octets(
    length=32,
  )
  let pub_bytes = BigInt::from_string(bench_ec_pub, radix=16).to_octets(
    length=64,
  )
  let signer = EcSigner::new_p256(priv_bytes.view(), pub_bytes.view())
  let verifier = EcVerifier::new_p256(pub_bytes.view())
  let claims = {
    let c = @mjwt.JwtClaims::new()
    c.set_subject("bench-ecdsa")
    c
  }
  let token = @mjwt.encode_with(signer, claims)
  it.bench(fn() {
    it.keep(
      @mjwt.decode_with(verifier, token) catch {
        _ =>
          {
            header: @mjwt.JwtHeader::new(""),
            claims: @mjwt.JwtClaims::new(),
            signature: FixedArray::make(0, b'\x00'),
          }
      },
    )
  })
}
