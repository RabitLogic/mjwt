///|
/// ECDSA signer & verifier for JWT (P-256 / ES256).
///
/// Implements ECDSA signature generation and verification over the NIST P-256
/// (secp256r1) curve.  Uses SHA-256 for hashing per RFC 7518 §3.4.
///
/// The internal scalar arithmetic uses a custom 256-bit field implementation
/// (`Scalar256`) with constant-time considerations.
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
pub struct Scalar256 {
  limbs : FixedArray[UInt64]
}

///|
pub fn Scalar256::zero() -> Scalar256 {
  { limbs: FixedArray::make(4, 0) }
}

///|
pub fn Scalar256::one() -> Scalar256 {
  { limbs: FixedArray::from_array([1, 0, 0, 0]) }
}

///|
pub fn Scalar256::from_bytes(be : BytesView) -> Scalar256 {
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
pub fn Scalar256::to_bytes(self : Scalar256) -> FixedArray[Byte] {
  let out = FixedArray::make(32, b'\x00')
  for i = 0; i < 4; i = i + 1 {
    let v = self.limbs[3 - i]
    for j = 0; j < 8; j = j + 1 {
      out[i * 8 + j] = ((v >> (56 - j * 8)) & 0xff).to_byte()
    }
  }
  out
}

///|
fn s_cmp(a : Scalar256, b : Scalar256) -> Int {
  for i = 3; i >= 0; i = i - 1 {
    if a.limbs[i] != b.limbs[i] {
      return if a.limbs[i] > b.limbs[i] { 1 } else { -1 }
    }
  }
  0
}

///|
fn s_add(a : Scalar256, b : Scalar256) -> Scalar256 {
  let r = Scalar256::zero()
  let mut carry = 0
  for i = 0; i < 4; i = i + 1 {
    let ai = a.limbs[i]
    let bi = b.limbs[i]
    let (sum, ov) = add_with_carry(ai, bi, carry)
    r.limbs[i] = sum
    carry = ov
  }
  s_mod_n(r)
}

///|
fn s_sub(a : Scalar256, b : Scalar256) -> Scalar256 {
  let r = Scalar256::zero()
  let mut borrow = 0
  for i = 0; i < 4; i = i + 1 {
    let ai = a.limbs[i]
    let bi = b.limbs[i]
    let (diff, bw) = sub_with_borrow(ai, bi, borrow)
    r.limbs[i] = diff
    borrow = bw
  }
  if borrow == 1 {
    return s_add(r, n_order)
  }
  r
}

///|
fn bit_is_set(n : UInt64, pos : Int) -> Bool {
  ((n >> pos) & 1) == 1
}

///|
fn s_mul(a : Scalar256, b : Scalar256) -> Scalar256 {
  let mut r = Scalar256::zero()
  let mut t = a
  for i = 0; i < 256; i = i + 1 {
    if bit_is_set(b.limbs[i / 64], i % 64) {
      r = s_add(r, t)
    }
    t = s_add(t, t)
  }
  s_mod_n(r)
}

///|
fn s_mod_n(a : Scalar256) -> Scalar256 {
  if s_cmp(a, n_order) >= 0 {
    return s_sub(a, n_order)
  }
  a
}

///|
/// Addition with carry for UInt64 (used in multi-limb arithmetic).
///
/// Returns `(sum, carry)` where `carry` is 1 if the result overflowed 64 bits.
fn add_with_carry(a : UInt64, b : UInt64, carry : Int) -> (UInt64, Int) {
  let s1 = if carry == 1 { a + 1 } else { a }
  let ov1 = if s1 == 0 && carry == 1 { 1 } else { 0 }
  let s2 = s1 + b
  let ov2 = if s2 < s1 { 1 } else { 0 }
  (s2, if ov1 == 1 || ov2 == 1 { 1 } else { 0 })
}

///|
/// Subtraction with borrow for UInt64.
///
/// Returns `(difference, borrow)` where `borrow` is 1 if underflow occurred.
fn sub_with_borrow(a : UInt64, b : UInt64, borrow : Int) -> (UInt64, Int) {
  let d1 = if borrow == 1 { a - 1 } else { a }
  let bw1 = if d1 > a && borrow == 1 { 1 } else { 0 }
  let d2 = d1 - b
  let bw2 = if d2 > d1 { 1 } else { 0 }
  (d2, if bw1 == 1 || bw2 == 1 { 1 } else { 0 })
}

// P-256 curve order n

///|
let n_order : Scalar256 = {
  limbs: FixedArray::from_array([
    0xf3b9cac2fc632551, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000,
  ]),
}

// P-256 prime p

///|
let _p_prime : Scalar256 = {
  limbs: FixedArray::from_array([
    0xffffffffffffffff, 0x00000000ffffffff, 0x0000000000000000, 0xffffffff00000001,
  ]),
}

// Generator point G

///|
let g_x : Scalar256 = {
  limbs: FixedArray::from_array([
    0xd898c296bdad4c8a, 0x0c0b0bf9db11c8e0, 0xedd9ae4c60dbba09, 0x6b17d1f2e12c4247,
  ]),
}

///|
let g_y : Scalar256 = {
  limbs: FixedArray::from_array([
    0x09f20c8d4c1d8bf1, 0x7c60c164108bac00, 0x8bcc3fbf26315281, 0x4fe342e2fe1a7f9b,
  ]),
}

// =============================================================================
//  Field arithmetic (mod p = P-256 prime)
// =============================================================================

///|
fn s_mod_p(a : Scalar256) -> Scalar256 {
  if s_cmp(a, _p_prime) >= 0 {
    return s_sub_p(a, _p_prime)
  }
  a
}

///|
fn s_add_p(a : Scalar256, b : Scalar256) -> Scalar256 {
  let r = Scalar256::zero()
  let mut carry = 0
  for i = 0; i < 4; i = i + 1 {
    let (sum, ov) = add_with_carry(a.limbs[i], b.limbs[i], carry)
    r.limbs[i] = sum
    carry = ov
  }
  s_mod_p(r)
}

///|
fn s_sub_p(a : Scalar256, b : Scalar256) -> Scalar256 {
  let r = Scalar256::zero()
  let mut borrow = 0
  for i = 0; i < 4; i = i + 1 {
    let (diff, bw) = sub_with_borrow(a.limbs[i], b.limbs[i], borrow)
    r.limbs[i] = diff
    borrow = bw
  }
  if borrow == 1 {
    return s_add_p(r, _p_prime)
  }
  r
}

///|
fn s_mul_p(a : Scalar256, b : Scalar256) -> Scalar256 {
  let mut r = Scalar256::zero()
  let mut t = a
  for i = 0; i < 256; i = i + 1 {
    if bit_is_set(b.limbs[i / 64], i % 64) {
      r = s_add_p(r, t)
    }
    t = s_add_p(t, t)
  }
  s_mod_p(r)
}

// =============================================================================
//  Modular inverse (Fermat, mod n — for scalars)
// =============================================================================

///|
fn mod_inv(a : Scalar256) -> Scalar256 {
  // a^(n-2) mod n
  let mut r = Scalar256::one()
  let mut b = a
  for i = 0; i < 256; i = i + 1 {
    if bit_is_set(n_order.limbs[i / 64], i % 64) {
      r = s_mul(r, b)
    }
    b = s_mul(b, b)
  }
  r
}

///|
/// Modular inverse modulo p (for field elements), uses Fermat: a^(p-2) mod p.
fn mod_inv_p(a : Scalar256) -> Scalar256 {
  let mut r = Scalar256::one()
  let mut b = a
  for i = 0; i < 256; i = i + 1 {
    if bit_is_set(_p_prime.limbs[i / 64], i % 64) {
      r = s_mul_p(r, b)
    }
    b = s_mul_p(b, b)
  }
  r
}

// =============================================================================
//  Point arithmetic (Jacobian projective coordinates)
//
//  Jacobian coordinates (X : Y : Z) represent affine point (X/Z^2, Y/Z^3).
//  The identity (point at infinity) is (1 : 1 : 0).
//
//  Benefit: point addition and doubling require NO modular inverses,
//  only multiplications. Only 1 inversion at the end to convert to affine.
//  For P-256 (a = -3), doubling uses the identity 3*(X-Z^2)*(X+Z^2) to
//  avoid computing Z^4.
// =============================================================================

///|
priv struct PointJac {
  x : Scalar256
  y : Scalar256
  z : Scalar256
}

///|
fn point_jac_zero() -> PointJac {
  { x: Scalar256::one(), y: Scalar256::one(), z: Scalar256::zero() }
}

///|
fn is_jac_zero(p : PointJac) -> Bool {
  p.z.limbs[0] == 0 &&
  p.z.limbs[1] == 0 &&
  p.z.limbs[2] == 0 &&
  p.z.limbs[3] == 0
}

///|
fn pt_dbl_jac(p : PointJac) -> PointJac {
  // Jacobian doubling for P-256 (a = -3).
  // Uses: t = 3*(X - Z^2)*(X + Z^2)  [= 3*X^2 + a*Z^4 where a = -3]
  // Then: S = 4*X*Y^2
  //       X3 = t^2 - 2*S
  //       Y3 = t*(S - X3) - 8*Y^4
  //       Z3 = 2*Y*Z
  let zsq = s_mul_p(p.z, p.z) // Z^2
  let x_m_zsq = s_sub_p(p.x, zsq) // X - Z^2
  let x_p_zsq = s_add_p(p.x, zsq) // X + Z^2
  let t = s_mul_p(x_m_zsq, x_p_zsq) // X^2 - Z^4
  let t = s_add_p(s_add_p(t, t), t) // 3*(X^2 - Z^4) = 3*X^2 + a*Z^4

  let ysq = s_mul_p(p.y, p.y) // Y^2
  let s = s_mul_p(p.x, ysq) // X*Y^2
  let s = s_add_p(s, s) // 2*X*Y^2
  let s = s_add_p(s, s) // 4*X*Y^2 = S

  let tsq = s_mul_p(t, t) // t^2
  let x3 = s_sub_p(tsq, s_add_p(s, s)) // t^2 - 2*S

  let ysq_sq = s_mul_p(ysq, ysq) // Y^4
  let y3 = s_sub_p(s, x3) // S - X3
  let y3 = s_mul_p(t, y3) // t*(S - X3)
  let y3 = s_sub_p(
    y3,
    s_add_p(s_add_p(ysq_sq, ysq_sq), s_add_p(ysq_sq, ysq_sq)),
  ) // - 8*Y^4

  let z3 = s_mul_p(p.y, p.z) // Y*Z
  let z3 = s_add_p(z3, z3) // 2*Y*Z

  { x: x3, y: y3, z: z3 }
}

///|
fn pt_add_jac(p1 : PointJac, p2 : PointJac) -> PointJac {
  // Jacobian addition: P3 = P1 + P2
  // Standard formulas:
  //   U1 = X1*Z2^2, U2 = X2*Z1^2
  //   S1 = Y1*Z2^3, S2 = Y2*Z1^3
  //   H = U2 - U1,   R = S2 - S1
  //   X3 = R^2 - H^3 - 2*U1*H^2
  //   Y3 = R*(U1*H^2 - X3) - S1*H^3
  //   Z3 = H*Z1*Z2
  if is_jac_zero(p1) {
    return p2
  }
  if is_jac_zero(p2) {
    return p1
  }

  let z1sq = s_mul_p(p1.z, p1.z)
  let z2sq = s_mul_p(p2.z, p2.z)
  let u1 = s_mul_p(p1.x, z2sq)
  let u2 = s_mul_p(p2.x, z1sq)
  let z1cu = s_mul_p(z1sq, p1.z)
  let z2cu = s_mul_p(z2sq, p2.z)
  let s1 = s_mul_p(p1.y, z2cu)
  let s2 = s_mul_p(p2.y, z1cu)

  // Check for doubling or inverse
  if s_cmp(u1, u2) == 0 {
    if s_cmp(s1, s2) == 0 {
      return pt_dbl_jac(p1)
    }
    return point_jac_zero() // P + (-P) = O
  }

  let h = s_sub_p(u2, u1)
  let r = s_sub_p(s2, s1)
  let hsq = s_mul_p(h, h) // H^2
  let hcu = s_mul_p(hsq, h) // H^3
  let u1_hsq = s_mul_p(u1, hsq) // U1*H^2

  let x3 = s_sub_p(s_sub_p(s_mul_p(r, r), hcu), s_add_p(u1_hsq, u1_hsq))
  let y3 = s_mul_p(r, s_sub_p(u1_hsq, x3))
  let y3 = s_sub_p(y3, s_mul_p(s1, hcu))
  let z3 = s_mul_p(h, s_mul_p(p1.z, p2.z))

  { x: x3, y: y3, z: z3 }
}

///|
/// Convert Jacobian point to affine (X/Z^2, Y/Z^3).
/// Requires 1 modular inverse.
fn point_jac_to_affine(p : PointJac) -> (Scalar256, Scalar256) {
  if is_jac_zero(p) {
    return (Scalar256::zero(), Scalar256::zero())
  }
  let z_inv = mod_inv_p(p.z)
  let z_inv_sq = s_mul_p(z_inv, z_inv)
  let x = s_mul_p(p.x, z_inv_sq)
  let y = s_mul_p(p.y, s_mul_p(z_inv_sq, z_inv))
  (x, y)
}

///|
/// Scalar multiplication returning Jacobian point (for chaining without inversion).
fn pt_mul_jac(k : Scalar256, px : Scalar256, py : Scalar256) -> PointJac {
  let mut r = point_jac_zero()
  let mut t = { x: px, y: py, z: Scalar256::one() }
  for i = 0; i < 256; i = i + 1 {
    if bit_is_set(k.limbs[i / 64], i % 64) {
      r = pt_add_jac(r, t)
    }
    t = pt_dbl_jac(t)
  }
  r
}

///|
/// Scalar multiplication returning affine coordinates.
fn pt_mul(
  k : Scalar256,
  px : Scalar256,
  py : Scalar256,
) -> (Scalar256, Scalar256) {
  point_jac_to_affine(pt_mul_jac(k, px, py))
}

// =============================================================================
//  Deterministic k (RFC 6979 simplified)
// =============================================================================

///|
fn gen_k(z : Scalar256, d : Scalar256) -> Scalar256 {
  let zb = z.to_bytes()
  let db = d.to_bytes()
  let input = FixedArray::make(64, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    input[i] = zb[i]
  }
  for i = 0; i < 32; i = i + 1 {
    input[32 + i] = db[i]
  }
  let h = @crypto.sha256(input.unsafe_reinterpret_as_bytes().view())
  Scalar256::from_bytes(h.unsafe_reinterpret_as_bytes().view())
}

// =============================================================================
//  ECDSA sign
// =============================================================================

///|
fn ecdsa_sign(z : Scalar256, d : Scalar256) -> (Scalar256, Scalar256) {
  let k = gen_k(z, d)
  let (r_x, _) = pt_mul(k, g_x, g_y)
  let r = s_mod_n(r_x)
  let k_inv = mod_inv(k)
  let s = s_mul(k_inv, s_add(z, s_mul(r, d)))
  (r, s)
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
  if s_cmp(r, n_order) >= 0 || s_cmp(s, n_order) >= 0 {
    return false
  }
  if r.limbs[0] == 0 && r.limbs[1] == 0 && r.limbs[2] == 0 && r.limbs[3] == 0 {
    return false
  }
  if s.limbs[0] == 0 && s.limbs[1] == 0 && s.limbs[2] == 0 && s.limbs[3] == 0 {
    return false
  }
  let s_inv = mod_inv(s)
  let u1 = s_mul(z, s_inv)
  let u2 = s_mul(r, s_inv)

  // P = u1*G + u2*Q — all in Jacobian, only 1 inversion at the end
  let p1 = pt_mul_jac(u1, g_x, g_y)
  let p2 = pt_mul_jac(u2, qx, qy)
  let p3 = pt_add_jac(p1, p2)
  let (p3x, _) = point_jac_to_affine(p3)

  s_mod_n(r).limbs[0] == p3x.limbs[0] &&
  s_mod_n(r).limbs[1] == p3x.limbs[1] &&
  s_mod_n(r).limbs[2] == p3x.limbs[2] &&
  s_mod_n(r).limbs[3] == p3x.limbs[3]
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
) -> EcSigner raise JwtError {
  guard priv_bytes.length() == 32 else {
    raise UnsupportedAlgorithm("P-256 private key must be 32 bytes")
  }
  guard pub_bytes.length() == 64 else {
    raise UnsupportedAlgorithm("P-256 public key must be 64 bytes")
  }
  {
    private_key: Scalar256::from_bytes(priv_bytes),
    public_key_x: Scalar256::from_bytes(pub_bytes[:32]),
    public_key_y: Scalar256::from_bytes(pub_bytes[32:]),
  }
}

///|
pub impl JwtSigner for EcSigner with fn alg_name(_ : EcSigner) -> String {
  "ES256"
}

///|
pub impl JwtSigner for EcSigner with fn sign(
  self : EcSigner,
  message : BytesView,
) -> FixedArray[Byte] raise JwtError {
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
pub extend EcSigner with JwtSigner::{alg_name, sign}

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
pub fn EcVerifier::new_p256(pub_bytes : BytesView) -> EcVerifier raise JwtError {
  guard pub_bytes.length() == 64 else {
    raise UnsupportedAlgorithm("P-256 public key must be 64 bytes")
  }
  {
    public_key_x: Scalar256::from_bytes(pub_bytes[:32]),
    public_key_y: Scalar256::from_bytes(pub_bytes[32:]),
  }
}

///|
pub impl JwtVerifier for EcVerifier with fn alg_name(_ : EcVerifier) -> String {
  "ES256"
}

///|
pub impl JwtVerifier for EcVerifier with fn verify(
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
pub extend EcVerifier with JwtVerifier::{alg_name, verify}
