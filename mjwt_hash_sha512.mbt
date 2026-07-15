///|
/// SHA-512 and SHA-384 implementations for MoonBit.
///
/// Pure-MoonBit implementations following **FIPS PUB 180-4** (Secure Hash
/// Standard).  Both use 64-bit words and 80 rounds.  SHA-384 is SHA-512 with
/// different initial values (IV) and a truncated 48-byte output.
///
/// # Verification
///
/// These implementations have been verified against:
/// - NIST SHA-384 known-answer tests: empty, "abc", 112-byte multi-block
/// - NIST SHA-512 known-answer tests: empty, "abc", 112-byte multi-block
/// - RFC 4231 HMAC test vectors for HS384 and HS512
/// - Cross-validated against Python `hashlib.sha384()` / `hashlib.sha512()`
///
/// # Usage (via `@crypto.CryptoHasher` trait)
///
/// ```moonbit
/// let h = Sha384::new()
/// h.update(data)
/// let hash = h.finalize()
/// ```

// =============================================================================
//  Internal primitives
// =============================================================================

///|
fn u64_rot_r(x : UInt64, n : Int) -> UInt64 {
  (x >> n) | (x << (64 - n))
}

///|
fn u64_to_8be(val : UInt64, buf : FixedArray[Byte], off : Int) -> Unit {
  buf[off] = ((val >> 56) & 0xff).to_byte()
  buf[off + 1] = ((val >> 48) & 0xff).to_byte()
  buf[off + 2] = ((val >> 40) & 0xff).to_byte()
  buf[off + 3] = ((val >> 32) & 0xff).to_byte()
  buf[off + 4] = ((val >> 24) & 0xff).to_byte()
  buf[off + 5] = ((val >> 16) & 0xff).to_byte()
  buf[off + 6] = ((val >> 8) & 0xff).to_byte()
  buf[off + 7] = (val & 0xff).to_byte()
}

///|
fn u8_8_to_u64_be(data : FixedArray[Byte], i : Int) -> UInt64 {
  let b0 = data[i].to_uint64()
  let b1 = data[i + 1].to_uint64()
  let b2 = data[i + 2].to_uint64()
  let b3 = data[i + 3].to_uint64()
  let b4 = data[i + 4].to_uint64()
  let b5 = data[i + 5].to_uint64()
  let b6 = data[i + 6].to_uint64()
  let b7 = data[i + 7].to_uint64()
  (b0 << 56) |
  (b1 << 48) |
  (b2 << 40) |
  (b3 << 32) |
  (b4 << 24) |
  (b5 << 16) |
  (b6 << 8) |
  b7
}

// =============================================================================
//  SHA-512 constants
// =============================================================================

///|
let k512 : FixedArray[UInt64] = [
  0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
  0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
  0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
  0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
  0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
  0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
  0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
  0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
  0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
  0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
  0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
  0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
  0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
  0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
  0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
  0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
  0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
  0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
  0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
  0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
]

///|
let iv512 : FixedArray[UInt64] = [
  0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
  0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
]

///|
let iv384 : FixedArray[UInt64] = [
  0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
  0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
]

// =============================================================================
//  Core state machine
// =============================================================================

///|
struct Sha512Ctx {
  reg : FixedArray[UInt64]
  mut len : UInt64
  buf : FixedArray[Byte]
  mut buf_idx : Int
  hsize : Int // output bytes: 64 for SHA-512, 48 for SHA-384
}

///|
fn ctx_new(iv : FixedArray[UInt64], hsize : Int) -> Sha512Ctx {
  let reg : FixedArray[UInt64] = FixedArray::make(8, 0)
  for i = 0; i < 8; i = i + 1 {
    reg[i] = iv[i]
  }
  {
    reg,
    len: 0,
    buf: FixedArray::make(128, Byte::default()),
    buf_idx: 0,
    hsize,
  }
}

///|
/// Process one 128-byte block through the SHA-512 compression function.
///
/// Follows FIPS PUB 180-4 section 6.4 (SHA-512).
/// - 80 rounds with 64-bit word operations
/// - Uses the message schedule W[0..79] expanded from the 16 input words
/// - Updates `ctx.reg` in-place (feed-forward: new = old + working vars)
fn block_compress(ctx : Sha512Ctx) -> Unit {
  let w : FixedArray[UInt64] = FixedArray::make(80, 0)
  for i = 0; i < 16; i = i + 1 {
    w[i] = u8_8_to_u64_be(ctx.buf, i * 8)
  }
  for i = 16; i < 80; i = i + 1 {
    let s0 = u64_rot_r(w[i - 15], 1) ^
      u64_rot_r(w[i - 15], 8) ^
      (w[i - 15] >> 7)
    let s1 = u64_rot_r(w[i - 2], 19) ^ u64_rot_r(w[i - 2], 61) ^ (w[i - 2] >> 6)
    w[i] = w[i - 16] + s0 + w[i - 7] + s1
  }
  let reg = ctx.reg
  let mut a = reg[0]
  let mut b = reg[1]
  let mut c = reg[2]
  let mut d = reg[3]
  let mut e = reg[4]
  let mut f = reg[5]
  let mut g = reg[6]
  let mut h = reg[7]
  for i = 0; i < 80; i = i + 1 {
    let s1 = u64_rot_r(e, 14) ^ u64_rot_r(e, 18) ^ u64_rot_r(e, 41)
    let ch = (e & f) ^ (e.lnot() & g)
    let t1 = h + s1 + ch + k512[i] + w[i]
    let s0 = u64_rot_r(a, 28) ^ u64_rot_r(a, 34) ^ u64_rot_r(a, 39)
    let maj = (a & b) ^ (a & c) ^ (b & c)
    let t2 = s0 + maj
    h = g
    g = f
    f = e
    e = d + t1
    d = c
    c = b
    b = a
    a = t1 + t2
  }
  reg[0] = reg[0] + a
  reg[1] = reg[1] + b
  reg[2] = reg[2] + c
  reg[3] = reg[3] + d
  reg[4] = reg[4] + e
  reg[5] = reg[5] + f
  reg[6] = reg[6] + g
  reg[7] = reg[7] + h
}

///|
/// Absorb arbitrary-length data into the hasher state.
///
/// Buffers data into 128-byte blocks and calls `block_compress` whenever
/// the buffer is full.  Tracks total byte count in `ctx.len` for the
/// final padding length field.
fn ctx_update(ctx : Sha512Ctx, data : BytesView) -> Unit {
  let n = data.length()
  let mut off = 0
  while off < n {
    let take = if 128 - ctx.buf_idx >= n - off {
      n - off
    } else {
      128 - ctx.buf_idx
    }
    for j = 0; j < take; j = j + 1 {
      ctx.buf[ctx.buf_idx + j] = data[off + j]
    }
    ctx.buf_idx = ctx.buf_idx + take
    off = off + take
    if ctx.buf_idx == 128 {
      block_compress(ctx)
      ctx.buf_idx = 0
    }
  }
  ctx.len = ctx.len + n.to_uint64()
}

///|
/// Finalise the hash: pad the message per SHA-512 rules and produce the
/// digest.
///
/// Padding (FIPS PUB 180-4 §5.1.2):
///   1. Append `0x80`
///   2. Pad with zeros until (length mod 128) == 112
///   3. Append 128-bit big-endian bit length
///   4. Compress the final block(s)
/// Returns the first `hsize` bytes of the state (64 for SHA-512, 48 for SHA-384).
fn ctx_finalize(ctx : Sha512Ctx) -> FixedArray[Byte] {
  let bit_len = ctx.len << 3
  ctx.buf[ctx.buf_idx] = b'\x80'
  ctx.buf_idx = ctx.buf_idx + 1
  if ctx.buf_idx > 112 {
    for i = ctx.buf_idx; i < 128; i = i + 1 {
      ctx.buf[i] = b'\x00'
    }
    block_compress(ctx)
    ctx.buf_idx = 0
  }
  for i = ctx.buf_idx; i < 112; i = i + 1 {
    ctx.buf[i] = b'\x00'
  }
  u64_to_8be(0, ctx.buf, 112)
  u64_to_8be(bit_len, ctx.buf, 120)
  block_compress(ctx)
  let out = FixedArray::make(ctx.hsize, b'\x00')
  for i = 0; i < ctx.hsize / 8; i = i + 1 {
    u64_to_8be(ctx.reg[i], out, i * 8)
  }
  out
}

// =============================================================================
//  SHA-512 hasher (implements CryptoHasher)
// =============================================================================

///|
pub struct Sha512 {
  ctx : Sha512Ctx
}

///|
pub fn Sha512::new() -> Sha512 {
  { ctx: ctx_new(iv512, 64) }
}

///|
pub impl @crypto.CryptoHasher for Sha512 with fn size(_ : Sha512) -> Int {
  64
}

///|
pub impl @crypto.CryptoHasher for Sha512 with fn block_size(_ : Sha512) -> Int {
  128
}

///|
pub impl @crypto.CryptoHasher for Sha512 with fn reset(self : Sha512) -> Unit {
  for i = 0; i < 8; i = i + 1 {
    self.ctx.reg[i] = iv512[i]
  }
  self.ctx.len = 0
  self.ctx.buf_idx = 0
  for i = 0; i < 128; i = i + 1 {
    self.ctx.buf[i] = b'\x00'
  }
}

///|
pub impl @crypto.CryptoHasher for Sha512 with fn update(
  self : Sha512,
  data : BytesView,
) -> Unit {
  ctx_update(self.ctx, data)
}

///|
pub impl @crypto.CryptoHasher for Sha512 with fn finalize_into(
  self : Sha512,
  buf : FixedArray[Byte],
  offset~ : Int,
) -> Unit {
  let out = ctx_finalize(self.ctx)
  for i = 0; i < 64; i = i + 1 {
    buf[offset + i] = out[i]
  }
}

///|
pub extend Sha512 with @crypto.CryptoHasher::{
  size,
  block_size,
  reset,
  update,
  finalize_into,
}

///|
/// Convenience: one-shot SHA-512 hash.
pub fn sha512(data : BytesView) -> FixedArray[Byte] {
  let h = Sha512::new()
  ctx_update(h.ctx, data)
  ctx_finalize(h.ctx)
}

// =============================================================================
//  SHA-384 hasher (truncated SHA-512 with different IV)
// =============================================================================

///|
pub struct Sha384 {
  ctx : Sha512Ctx
}

///|
pub fn Sha384::new() -> Sha384 {
  { ctx: ctx_new(iv384, 48) }
}

///|
pub impl @crypto.CryptoHasher for Sha384 with fn size(_ : Sha384) -> Int {
  48
}

///|
pub impl @crypto.CryptoHasher for Sha384 with fn block_size(_ : Sha384) -> Int {
  128
}

///|
pub impl @crypto.CryptoHasher for Sha384 with fn reset(self : Sha384) -> Unit {
  for i = 0; i < 8; i = i + 1 {
    self.ctx.reg[i] = iv384[i]
  }
  self.ctx.len = 0
  self.ctx.buf_idx = 0
  for i = 0; i < 128; i = i + 1 {
    self.ctx.buf[i] = b'\x00'
  }
}

///|
pub impl @crypto.CryptoHasher for Sha384 with fn update(
  self : Sha384,
  data : BytesView,
) -> Unit {
  ctx_update(self.ctx, data)
}

///|
pub impl @crypto.CryptoHasher for Sha384 with fn finalize_into(
  self : Sha384,
  buf : FixedArray[Byte],
  offset~ : Int,
) -> Unit {
  let out = ctx_finalize(self.ctx)
  for i = 0; i < 48; i = i + 1 {
    buf[offset + i] = out[i]
  }
}

///|
pub extend Sha384 with @crypto.CryptoHasher::{
  size,
  block_size,
  reset,
  update,
  finalize_into,
}

///|
/// Convenience: one-shot SHA-384 hash.
pub fn sha384(data : BytesView) -> FixedArray[Byte] {
  let h = Sha384::new()
  ctx_update(h.ctx, data)
  ctx_finalize(h.ctx)
}
