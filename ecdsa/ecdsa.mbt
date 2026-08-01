///|
/// ECDSA signer & verifier for JWT (P-256 / ES256).
///
/// Implements ECDSA signature generation and verification over the NIST P-256
/// (secp256r1) curve.  Uses SHA-256 for hashing per RFC 7518 §3.4.
///
/// The internal field/scalar arithmetic is done with `@bigint.BigInt` (native
/// big integers) mod the P-256 prime and curve order, which is far faster than
/// a pure-MoonBit limb implementation.
///
/// # Supported algorithms
///
/// | Algorithm | Curve      | Hash    | Status |
/// |-----------|------------|---------|--------|
/// | ES256     | P-256      | SHA-256 | ✅     |
/// | ES384     | P-384      | SHA-384 | ⏳     |
/// | ES512     | P-521      | SHA-512 | ⏳     |
///
/// # Usage
///
/// ```moonbit
/// let signer = EcSigner::new_p256(priv_bytes, pub_bytes)?
/// let token = @mjwt.encode_with(signer, claims)?
/// let verifier = EcVerifier::new_p256(pub_bytes)?
/// let decoded = @mjwt.decode_with(verifier, token)?
/// ```
///
/// # Key format
///
/// - Private key: 32 bytes (big-endian scalar)
/// - Public key:  64 bytes (uncompressed, x‖y, each 32 bytes big-endian)

// =============================================================================
//  Scalar256 — 256-bit unsigned integer (4 × UInt64, little-endian limbs)
// =============================================================================

///|
struct Scalar256 {
  limbs : FixedArray[UInt64]
}

///|
fn Scalar256::from_bytes(be : BytesView) -> Scalar256 {
  guard be.length() == 32 else { abort("need 32 bytes") }
  let ls : FixedArray[UInt64] = FixedArray::make(4, 0)
  for i = 0; i < 4; i = i + 1 {
    let mut v : UInt64 = 0
    for j = 0; j < 8; j = j + 1 {
      v = (v << 8) | be[i * 8 + j].to_uint64()
    }
    ls[3 - i] = v
  }
  { limbs: ls }
}

///|
fn Scalar256::to_bytes(self : Scalar256) -> FixedArray[Byte] {
  let out = FixedArray::make(32, b'\x00')
  for i = 0; i < 4; i = i + 1 {
    let v = self.limbs[3 - i]
    for j = 0; j < 8; j = j + 1 {
      out[i * 8 + j] = ((v >> (56 - j * 8)) & 0xff).to_byte()
    }
  }
  out
}

// =============================================================================
//  P-256 constants (as BigInt)
// =============================================================================

///|
let bi_p : BigInt = BigInt::from_string(
  "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
  radix=16,
)

///|
let bi_n : BigInt = BigInt::from_string(
  "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
  radix=16,
)

///|
let bi_n_minus_2 : BigInt = BigInt::from_string(
  "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f",
  radix=16,
)

///|
let bi_p_minus_2 : BigInt = BigInt::from_string(
  "ffffffff00000001000000000000000000000000fffffffffffffffffffffffd",
  radix=16,
)

// Generator point G (NIST P-256 / secp256r1)

///|
let bi_gx : BigInt = BigInt::from_string(
  "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
  radix=16,
)

///|
let bi_gy : BigInt = BigInt::from_string(
  "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
  radix=16,
)

///|
/// Curve coefficient b of the P-256 short-Weierstrass equation y^2 = x^3 - 3x + b.
let bi_b : BigInt = BigInt::from_string(
  "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
  radix=16,
)

///|
/// floor((n-1)/2) — the low-S boundary: a signature is "low-S" when s <= n/2.
let bi_n_half : BigInt = (bi_n - 1N) / 2N
// =============================================================================
//  Conversions (Scalar256 <-> BigInt)
// =============================================================================

///|
/// `BigInt::from_octets` wrapper that works around a MoonBit core bug: on an
/// all-zero byte string it returns a NON-canonical zero (`len > 0` with all-zero
/// limbs), which breaks `==`, `<`, and `to_string`. That would silently defeat
/// the r=0/s=0 rejection in `ecdsa_verify` and the d=0 check in
/// `EcSigner::new_p256`, so all-zero input is normalized to the canonical `0N`.
///
/// Every byte-to-`BigInt` conversion in this package MUST go through this
/// helper (never raw `BigInt::from_octets`) so the workaround stays complete.
fn bi_from_octets(data : BytesView, signum? : Int = 1) -> BigInt {
  let mut all_zero = true
  for i = 0; i < data.length(); i = i + 1 {
    if data[i] != b'\x00' {
      all_zero = false
      break
    }
  }
  if all_zero {
    return 0N
  }
  BigInt::from_octets(data, signum~)
}

///|
fn s_to_bi(s : Scalar256) -> BigInt {
  bi_from_octets(s.to_bytes().unsafe_reinterpret_as_bytes().view(), signum=1)
}

///|
fn bi_to_s(x : BigInt) -> Scalar256 {
  Scalar256::from_bytes(x.to_octets(length=32).view())
}

// =============================================================================
//  Field arithmetic (mod p = P-256 prime)
// =============================================================================

///|
fn fp_add(a : BigInt, b : BigInt) -> BigInt {
  (a + b) % bi_p
}

///|
fn fp_sub(a : BigInt, b : BigInt) -> BigInt {
  (a - b + bi_p) % bi_p
}

///|
fn fp_mul(a : BigInt, b : BigInt) -> BigInt {
  a * b % bi_p
}

///|
fn fp_inv(a : BigInt) -> BigInt {
  a.pow(bi_p_minus_2, modulus=bi_p)
}

// =============================================================================
//  Scalar arithmetic (mod n = P-256 curve order)
// =============================================================================

///|
fn sn_add(a : BigInt, b : BigInt) -> BigInt {
  (a + b) % bi_n
}

///|
fn sn_mul(a : BigInt, b : BigInt) -> BigInt {
  a * b % bi_n
}

///|
fn sn_inv(a : BigInt) -> BigInt {
  a.pow(bi_n_minus_2, modulus=bi_n)
}

// =============================================================================
//  Point arithmetic (Jacobian projective coordinates, BigInt field elements)
//
//  Jacobian coordinates (X : Y : Z) represent affine point (X/Z^2, Y/Z^3).
//  The identity (point at infinity) is (1 : 1 : 0).
//
//  Benefit: point addition and doubling require NO modular inverses, only
//  multiplications. Only 1 inversion at the end to convert to affine.
//  For P-256 (a = -3), doubling uses 3*(X-Z^2)*(X+Z^2) to avoid computing Z^4.
// =============================================================================

///|
priv struct PointBi {
  x : BigInt
  y : BigInt
  z : BigInt
}

///|
fn pt_bi_zero() -> PointBi {
  { x: 1N, y: 1N, z: 0N }
}

///|
fn pt_bi_is_zero(p : PointBi) -> Bool {
  p.z == 0N
}

///|
fn pt_dbl_bi(p : PointBi) -> PointBi {
  // Jacobian doubling for P-256 (a = -3).
  let zsq = fp_mul(p.z, p.z) // Z^2
  let t = fp_mul(fp_sub(p.x, zsq), fp_add(p.x, zsq)) // X^2 - Z^4
  let t = fp_add(fp_add(t, t), t) // 3*(X^2 - Z^4)
  let ysq = fp_mul(p.y, p.y) // Y^2
  let s = fp_mul(p.x, ysq) // X*Y^2
  let s = fp_add(s, s) // 2*X*Y^2
  let s = fp_add(s, s) // 4*X*Y^2 = S
  let x3 = fp_sub(fp_mul(t, t), fp_add(s, s)) // t^2 - 2*S
  let y3 = fp_mul(t, fp_sub(s, x3)) // t*(S - X3)
  let ysq_sq = fp_mul(ysq, ysq) // Y^4
  let four_y4 = fp_add(fp_add(ysq_sq, ysq_sq), fp_add(ysq_sq, ysq_sq)) // 4*Y^4
  let y3 = fp_sub(y3, fp_add(four_y4, four_y4)) // - 8*Y^4
  let z3 = fp_add(fp_mul(p.y, p.z), fp_mul(p.y, p.z)) // 2*Y*Z
  { x: x3, y: y3, z: z3 }
}

///|
fn pt_add_bi(p1 : PointBi, p2 : PointBi) -> PointBi {
  // Jacobian addition (add-2007-bl formulas).
  if pt_bi_is_zero(p1) {
    return p2
  }
  if pt_bi_is_zero(p2) {
    return p1
  }
  let z1sq = fp_mul(p1.z, p1.z)
  let z2sq = fp_mul(p2.z, p2.z)
  let u1 = fp_mul(p1.x, z2sq)
  let u2 = fp_mul(p2.x, z1sq)
  let s1 = fp_mul(p1.y, fp_mul(z2sq, p2.z))
  let s2 = fp_mul(p2.y, fp_mul(z1sq, p1.z))
  if u1 == u2 {
    if s1 == s2 {
      return pt_dbl_bi(p1)
    }
    return pt_bi_zero() // P + (-P) = O
  }
  let h = fp_sub(u2, u1)
  let r = fp_sub(s2, s1)
  let hsq = fp_mul(h, h) // H^2
  let hcu = fp_mul(hsq, h) // H^3
  let u1hsq = fp_mul(u1, hsq) // U1*H^2
  let x3 = fp_sub(fp_sub(fp_mul(r, r), hcu), fp_add(u1hsq, u1hsq))
  let y3 = fp_mul(r, fp_sub(u1hsq, x3))
  let y3 = fp_sub(y3, fp_mul(s1, hcu))
  let z3 = fp_mul(h, fp_mul(p1.z, p2.z))
  { x: x3, y: y3, z: z3 }
}

///|
/// Convert Jacobian point to affine (X/Z^2, Y/Z^3). Requires 1 modular inverse.
fn pt_affine_bi(p : PointBi) -> (BigInt, BigInt) {
  if pt_bi_is_zero(p) {
    return (0N, 0N)
  }
  let z_inv = fp_inv(p.z)
  let z_inv_sq = fp_mul(z_inv, z_inv)
  (fp_mul(p.x, z_inv_sq), fp_mul(p.y, fp_mul(z_inv_sq, z_inv)))
}

///|
/// Returns `true` if (x, y) is a valid affine point on the P-256 curve:
/// coordinates reduced mod p and satisfying y^2 = x^3 - 3x + b (mod p).
///
/// The point at infinity has no affine representation and (0, 0) does not
/// satisfy the equation (b != 0), so this check also excludes it.
fn point_on_curve(x : BigInt, y : BigInt) -> Bool {
  if x < 0N || x >= bi_p || y < 0N || y >= bi_p {
    return false
  }
  let lhs = fp_mul(y, y) // y^2
  let x3 = fp_mul(fp_mul(x, x), x) // x^3
  let rhs = fp_add(fp_sub(x3, fp_mul(3N, x)), bi_b) // x^3 - 3x + b
  lhs == rhs
}

///|
/// Scalar multiplication via the Montgomery ladder. Performs exactly one point
/// addition and one doubling per bit regardless of the scalar's bit values, so
/// the operation sequence is independent of the (secret) scalar k.
///
/// Note: the branch on each bit only decides *which* register receives the
/// add vs. the double — both branches execute one add + one double, so the
/// timing is uniform at the algorithm level.
fn pt_mul_bi(k : BigInt, gx : BigInt, gy : BigInt) -> PointBi {
  let mut r0 = pt_bi_zero()
  let mut r1 : PointBi = { x: gx, y: gy, z: 1N }
  for i = 255; i >= 0; i = i - 1 {
    if ((k >> i) & 1N) != 0N {
      r0 = pt_add_bi(r0, r1)
      r1 = pt_dbl_bi(r1)
    } else {
      r1 = pt_add_bi(r0, r1)
      r0 = pt_dbl_bi(r0)
    }
  }
  r0
}

// =============================================================================
//  Deterministic k — standard RFC 6979
// =============================================================================

///|
/// Concatenate byte arrays into one buffer.
fn concat(parts : Array[FixedArray[Byte]]) -> FixedArray[Byte] {
  let mut len = 0
  for p in parts {
    len = len + p.length()
  }
  let out = FixedArray::make(len, b'\x00')
  let mut off = 0
  for p in parts {
    for i = 0; i < p.length(); i = i + 1 {
      out[off + i] = p[i]
    }
    off = off + p.length()
  }
  out
}

///|
/// HMAC-SHA256 with `key` over the concatenation of `parts`.
fn hmac_bytes(
  key : FixedArray[Byte],
  parts : Array[FixedArray[Byte]],
) -> FixedArray[Byte] {
  let msg = concat(parts)
  @crypto.hmac(
    @crypto.SHA256::new(),
    key.unsafe_reinterpret_as_bytes().view(),
    msg.unsafe_reinterpret_as_bytes().view(),
  )
}

///|
/// RFC 6979 deterministic nonce k for P-256 / SHA-256.
///
/// qlen = 256, rolen = 32, hlen = 256, so bits2int/int2octets are trivial.
/// Implements the HMAC_DRBG construction of RFC 6979 §3.2.
fn gen_k(z : BigInt, d : BigInt) -> BigInt {
  // int2octets(x) and bits2octets(h1) = int2octets(bits2int(h1) mod q)
  let int2octets_x = d.to_octets(length=32).to_fixedarray()
  let bits2octets_h1 = (z % bi_n).to_octets(length=32).to_fixedarray()
  let zero_byte = FixedArray::from_array([b'\x00'])
  let one_byte = FixedArray::from_array([b'\x01'])

  // Steps 2–3: V = 0x01*32, K = 0x00*32
  let mut v = FixedArray::make(32, b'\x01')
  let mut k = FixedArray::make(32, b'\x00')

  // Steps 4–7: seed the HMAC_DRBG
  k = hmac_bytes(k, [v, zero_byte, int2octets_x, bits2octets_h1])
  v = hmac_bytes(k, [v])
  k = hmac_bytes(k, [v, one_byte, int2octets_x, bits2octets_h1])
  v = hmac_bytes(k, [v])

  // Step 8: generate candidates until 1 <= k < q
  gen_k_candidate(v, k)
}

///|
/// One HMAC_DRBG candidate generation step for RFC 6979. Recurses on the
/// astronomically unlikely rejection (k out of [1, q-1], probability ~2^-256).
fn gen_k_candidate(v : FixedArray[Byte], k : FixedArray[Byte]) -> BigInt {
  let v1 = hmac_bytes(k, [v])
  let kk = bi_from_octets(v1.unsafe_reinterpret_as_bytes().view(), signum=1)
  if kk >= 1N && kk < bi_n {
    return kk
  }
  let zero_byte = FixedArray::from_array([b'\x00'])
  let k1 = hmac_bytes(k, [v1, zero_byte])
  let v2 = hmac_bytes(k1, [v1])
  gen_k_candidate(v2, k1)
}

// =============================================================================
//  ECDSA sign
// =============================================================================

///|
fn ecdsa_sign(z : Scalar256, d : Scalar256) -> (Scalar256, Scalar256) {
  let zb = s_to_bi(z)
  let db = s_to_bi(d)
  let k = gen_k(zb, db)
  let (r_x, _) = pt_affine_bi(pt_mul_bi(k, bi_gx, bi_gy))
  let r = r_x % bi_n
  let k_inv = sn_inv(k)
  let mut s = sn_mul(k_inv, sn_add(zb, sn_mul(r, db)))
  // Normalize to low-S (BIP-0062 style): s in [1, n/2]. (r, s) and (r, n-s)
  // are both valid, but low-S is the modern strict convention.
  if s > bi_n_half {
    s = bi_n - s
  }
  (bi_to_s(r), bi_to_s(s))
}

// =============================================================================
//  ECDSA verify
// =============================================================================

///|
fn ecdsa_verify(
  z : Scalar256,
  qx : Scalar256,
  qy : Scalar256,
  r : Scalar256,
  s : Scalar256,
) -> Bool {
  let zb = s_to_bi(z)
  let rb = s_to_bi(r)
  let sb = s_to_bi(s)
  if rb >= bi_n || sb >= bi_n {
    return false
  }
  if rb == 0N || sb == 0N {
    return false
  }
  // Enforce low-S: reject high-S signatures.
  if sb > bi_n_half {
    return false
  }
  let s_inv = sn_inv(sb)
  let u1 = sn_mul(zb, s_inv)
  let u2 = sn_mul(rb, s_inv)

  // P = u1*G + u2*Q — all in Jacobian, only 1 inversion at the end
  let p1 = pt_mul_bi(u1, bi_gx, bi_gy)
  let p2 = pt_mul_bi(u2, s_to_bi(qx), s_to_bi(qy))
  let p3 = pt_add_bi(p1, p2)
  let (p3x, _) = pt_affine_bi(p3)

  p3x % bi_n == rb
}

// =============================================================================
//  EcSigner
// =============================================================================

///|
/// ECDSA signer for P-256 (ES256).
pub struct EcSigner {
  private_key : Scalar256
  public_key_x : Scalar256
  public_key_y : Scalar256
}

///|
/// Create an `EcSigner` for ES256.
///
/// - `priv_bytes` — 32 bytes (big-endian scalar)
/// - `pub_bytes`  — 64 bytes (uncompressed: x || y, each 32 bytes big-endian)
pub fn EcSigner::new_p256(
  priv_bytes : BytesView,
  pub_bytes : BytesView,
) -> EcSigner raise @mjwt.JwtError {
  guard priv_bytes.length() == 32 else {
    raise @mjwt.UnsupportedAlgorithm("P-256 private key must be 32 bytes")
  }
  guard pub_bytes.length() == 64 else {
    raise @mjwt.UnsupportedAlgorithm("P-256 public key must be 64 bytes")
  }
  let d = s_to_bi(Scalar256::from_bytes(priv_bytes))
  if d < 1N || d >= bi_n {
    raise @mjwt.UnsupportedAlgorithm("P-256 private key must be in [1, n-1]")
  }
  let qx = s_to_bi(Scalar256::from_bytes(pub_bytes[:32]))
  let qy = s_to_bi(Scalar256::from_bytes(pub_bytes[32:]))
  if !point_on_curve(qx, qy) {
    raise @mjwt.UnsupportedAlgorithm(
      "P-256 public key is not a valid curve point",
    )
  }
  {
    private_key: Scalar256::from_bytes(priv_bytes),
    public_key_x: Scalar256::from_bytes(pub_bytes[:32]),
    public_key_y: Scalar256::from_bytes(pub_bytes[32:]),
  }
}

///|
pub impl @mjwt.JwtSigner for EcSigner with fn alg_name(_ : EcSigner) -> String {
  "ES256"
}

///|
pub impl @mjwt.JwtSigner for EcSigner with fn sign(
  self : EcSigner,
  message : BytesView,
) -> FixedArray[Byte] raise @mjwt.JwtError {
  let hash = @crypto.sha256(message)
  let z = Scalar256::from_bytes(hash.unsafe_reinterpret_as_bytes().view())
  let (r, s) = ecdsa_sign(z, self.private_key)
  // P1363 format: r || s (32 bytes each)
  let rb = r.to_bytes()
  let sb = s.to_bytes()
  let out = FixedArray::make(64, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    out[i] = rb[i]
  }
  for i = 0; i < 32; i = i + 1 {
    out[32 + i] = sb[i]
  }
  out
}

///|
pub extend EcSigner with @mjwt.JwtSigner::{alg_name, sign}

// =============================================================================
//  EcVerifier
// =============================================================================

///|
/// ECDSA verifier for P-256 (ES256).
pub struct EcVerifier {
  public_key_x : Scalar256
  public_key_y : Scalar256
}

///|
/// Create an `EcVerifier` for ES256.
///
/// - `pub_bytes` — 64 bytes (uncompressed: x || y)
pub fn EcVerifier::new_p256(
  pub_bytes : BytesView,
) -> EcVerifier raise @mjwt.JwtError {
  guard pub_bytes.length() == 64 else {
    raise @mjwt.UnsupportedAlgorithm("P-256 public key must be 64 bytes")
  }
  let qx = s_to_bi(Scalar256::from_bytes(pub_bytes[:32]))
  let qy = s_to_bi(Scalar256::from_bytes(pub_bytes[32:]))
  if !point_on_curve(qx, qy) {
    raise @mjwt.UnsupportedAlgorithm(
      "P-256 public key is not a valid curve point",
    )
  }
  {
    public_key_x: Scalar256::from_bytes(pub_bytes[:32]),
    public_key_y: Scalar256::from_bytes(pub_bytes[32:]),
  }
}

///|
pub impl @mjwt.JwtVerifier for EcVerifier with fn alg_name(_ : EcVerifier) -> String {
  "ES256"
}

///|
pub impl @mjwt.JwtVerifier for EcVerifier with fn verify(
  self : EcVerifier,
  message : BytesView,
  signature : BytesView,
) -> Bool {
  guard signature.length() == 64 else { return false }
  let hash = @crypto.sha256(message)
  let z = Scalar256::from_bytes(hash.unsafe_reinterpret_as_bytes().view())
  let r = Scalar256::from_bytes(signature[:32])
  let s = Scalar256::from_bytes(signature[32:])
  ecdsa_verify(z, self.public_key_x, self.public_key_y, r, s)
}

///|
pub extend EcVerifier with @mjwt.JwtVerifier::{alg_name, verify}
