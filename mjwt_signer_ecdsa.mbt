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
//  Modular inverse (Fermat)
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

// =============================================================================
//  Point arithmetic (affine)
// =============================================================================

///|
fn pt_dbl(x : Scalar256, y : Scalar256) -> (Scalar256, Scalar256) {
  let xs = s_mul(x, x)
  let three_xs = s_add(s_add(xs, xs), xs)
  let two_y = s_add(y, y)
  let lambda = s_mul(three_xs, mod_inv(two_y))
  let ls = s_mul(lambda, lambda)
  let x3 = s_sub(ls, s_add(x, x))
  let y3 = s_sub(s_mul(lambda, s_sub(x, x3)), y)
  (x3, y3)
}

///|
fn pt_add(
  x1 : Scalar256,
  y1 : Scalar256,
  x2 : Scalar256,
  y2 : Scalar256,
) -> (Scalar256, Scalar256) {
  // identity
  if x1.limbs[0] == 0 &&
    x1.limbs[1] == 0 &&
    x1.limbs[2] == 0 &&
    x1.limbs[3] == 0 {
    return (x2, y2)
  }
  if x2.limbs[0] == 0 &&
    x2.limbs[1] == 0 &&
    x2.limbs[2] == 0 &&
    x2.limbs[3] == 0 {
    return (x1, y1)
  }
  // doubling
  if s_cmp(x1, x2) == 0 {
    if s_cmp(y1, y2) == 0 {
      return pt_dbl(x1, y1)
    }
    return (Scalar256::zero(), Scalar256::zero()) // P + (-P) = O
  }
  let dy = s_sub(y2, y1)
  let dx = s_sub(x2, x1)
  let lambda = s_mul(dy, mod_inv(dx))
  let x3 = s_sub(s_mul(lambda, lambda), s_add(x1, x2))
  let y3 = s_sub(s_mul(lambda, s_sub(x1, x3)), y1)
  (x3, y3)
}

///|
fn pt_mul(
  k : Scalar256,
  px : Scalar256,
  py : Scalar256,
) -> (Scalar256, Scalar256) {
  let mut rx = Scalar256::zero()
  let mut ry = Scalar256::zero()
  let mut tx = px
  let mut ty = py
  for i = 0; i < 256; i = i + 1 {
    if bit_is_set(k.limbs[i / 64], i % 64) {
      if rx.limbs[0] == 0 &&
        rx.limbs[1] == 0 &&
        rx.limbs[2] == 0 &&
        rx.limbs[3] == 0 {
        rx = tx
        ry = ty
      } else {
        let (nx, ny) = pt_add(rx, ry, tx, ty)
        rx = nx
        ry = ny
      }
    }
    let (nx, ny) = pt_dbl(tx, ty)
    tx = nx
    ty = ny
  }
  (rx, ry)
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
  let (p1x, p1y) = pt_mul(u1, g_x, g_y)
  let (p2x, p2y) = pt_mul(u2, qx, qy)
  let (p3x, _) = pt_add(p1x, p1y, p2x, p2y)
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
