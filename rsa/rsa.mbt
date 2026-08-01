///|
/// RSA signer & verifier for JWT (PKCS#1 v1.5).
///
/// Implements the RSASSA-PKCS1-v1_5 signature scheme with SHA-256 hash,
/// as specified in RFC 8017 §8.2 and RFC 7518 §3.3.
///
/// # Supported algorithms
///
/// | Algorithm | Hash    | Status |
/// |-----------|---------|--------|
/// | RS256     | SHA-256 | ✅     |
/// | RS384     | SHA-384 | ⏳     |
/// | RS512     | SHA-512 | ⏳     |
///
/// # Usage
///
/// ```moonbit
/// let signer = RsaSigner::new(n_bytes, d_bytes, "RS256")?
/// let token = @mjwt.encode_with(signer, claims)?
///
/// let verifier = RsaVerifier::new(n_bytes, e_bytes, "RS256")?
/// let decoded = @mjwt.decode_with(verifier, token)?
/// ```
///
/// # Key format
///
/// All parameters are big-endian byte arrays:
/// - `n_bytes` — RSA modulus (k bytes, where k is the octet length)
/// - `d_bytes` — RSA private exponent (k bytes)
/// - `e_bytes` — RSA public exponent (commonly 3 bytes: `0x010001` = 65537)
///
/// # Notes
///
/// - `BigInt::from_octets` treats input bytes as **signed** (two's complement).
///   If the first byte has MSB=1, the value becomes negative.  The constructors
///   handle this transparently by prepending a `\x00` byte.
/// - The modulus **must** be large enough so that `k - hash_len - 19 ≥ 8`
///   (i.e. at least 8 padding bytes).  A 2048-bit key (k=256) satisfies this
///   for SHA-256.

// =============================================================================
//  DER prefix for DigestInfo
// =============================================================================

///|
fn der_prefix(hash_len : Int) -> FixedArray[Byte] {
  match hash_len {
    32 =>
      FixedArray::from_array([
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
        0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
      ])
    48 =>
      FixedArray::from_array([
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
        0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
      ])
    64 =>
      FixedArray::from_array([
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
        0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
      ])
    _ => abort("unsupported hash length")
  }
}

// =============================================================================
//  RsaSigner
// =============================================================================

///|
/// RSA signer using PKCS#1 v1.5 signature scheme.
///
/// - `n` — RSA modulus
/// - `d` — private exponent
/// - `e` — public exponent (used only for blinding)
/// - `hash_len` — output length of the hash (32=SHA256, 48=SHA384, 64=SHA512)
pub struct RsaSigner {
  n : BigInt
  d : BigInt
  e : BigInt
  hash_len : Int
  alg : String
}

///|
/// Create an `RsaSigner`.
///
/// - `n_bytes` — modulus in big-endian bytes
/// - `d_bytes` — private exponent in big-endian bytes
/// - `alg` — `"RS256"`, `"RS384"`, or `"RS512"`

///|
/// `BigInt::from_octets` wrapper working around the MoonBit core zero bug (also
/// present in `ecdsa/ecdsa.mbt`): an all-zero byte string yields a non-canonical
/// zero that breaks `==`/`<`/`to_string`. All-zero input is normalized to `0N`.
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
/// Convert big-endian bytes to an unsigned `BigInt`.
///
/// MoonBit's `BigInt::from_octets` interprets bytes as signed (two's complement),
/// so when the most significant byte has MSB=1 (e.g. `0xAB…`), the resulting
/// `BigInt` would be **negative** — which is incorrect for RSA modulus or
/// exponent values that are inherently unsigned.
///
/// This function prepends a `\x00` byte to force an unsigned interpretation,
/// then delegates to `bi_from_octets` (which also normalizes all-zero input to
/// the canonical `0N`, working around the MoonBit core `from_octets` zero bug).
fn unsigned_bigint_from_bytes(data : BytesView) -> BigInt {
  let padded = FixedArray::make(data.length() + 1, b'\x00')
  for i = 0; i < data.length(); i = i + 1 {
    padded[i + 1] = data[i]
  }
  bi_from_octets(padded.unsafe_reinterpret_as_bytes().view())
}

///|
pub fn RsaSigner::new(
  n_bytes : BytesView,
  d_bytes : BytesView,
  alg : String,
  e_bytes? : Bytes = b"\x01\x00\x01",
) -> RsaSigner raise @mjwt.JwtError {
  let (hash_len, alg_name) = match alg {
    "RS256" => (32, "RS256")
    "RS384" => (48, "RS384")
    "RS512" => (64, "RS512")
    _ => raise @mjwt.UnsupportedAlgorithm(alg)
  }
  let n = unsigned_bigint_from_bytes(n_bytes)
  let d = unsigned_bigint_from_bytes(d_bytes)
  if n.bit_length() < 2048 {
    raise @mjwt.CryptoError("RSA modulus must be at least 2048 bits")
  }
  let e = unsigned_bigint_from_bytes(e_bytes.view())
  { n, d, e, hash_len, alg: alg_name }
}

///|
/// Extended Euclidean algorithm. Returns (g, x, y) such that a*x + b*y = g
/// where g = gcd(a, b). Used to compute modular inverses for RSA blinding.
fn egcd(a : BigInt, b : BigInt) -> (BigInt, BigInt, BigInt) {
  let mut old_r = a
  let mut r = b
  let mut old_s = 1N
  let mut s = 0N
  let mut old_t = 0N
  let mut t = 1N
  while r != 0N {
    let q = old_r / r
    let tmp_r = old_r - q * r
    old_r = r
    r = tmp_r
    let tmp_s = old_s - q * s
    old_s = s
    s = tmp_s
    let tmp_t = old_t - q * t
    old_t = t
    t = tmp_t
  }
  (old_r, old_s, old_t)
}

///|
/// Modular inverse of `a` modulo `m`, or `None` when gcd(a, m) != 1.
fn mod_inverse(a : BigInt, m : BigInt) -> BigInt? {
  let (g, x, _) = egcd(a, m)
  if g != 1N {
    return None
  }
  Some((x % m + m) % m)
}

///|
/// Generate a random RSA blinding pair (r, r^-1 mod n) with gcd(r, n) = 1.
/// The blinding factor `r` must be secret and unpredictable, hence it is drawn
/// from `@random.Rand::new()`, which seeds from OS entropy.
fn blind_pair(n : BigInt) -> (BigInt, BigInt) {
  let rand = @random.Rand::new()
  blind_pair_step(rand, n)
}

///|
/// One rejection-sampling step for `blind_pair` (retries if gcd(r, n) != 1,
/// which happens with probability ~2^-1024 for a 2048-bit modulus).
fn blind_pair_step(rand : @random.Rand, n : BigInt) -> (BigInt, BigInt) {
  let r = rand.bigint(n.bit_length()).mod(n)
  if r >= 2N {
    match mod_inverse(r, n) {
      Some(inv) => return (r, inv)
      None => ()
    }
  }
  blind_pair_step(rand, n)
}

///|
pub impl @mjwt.JwtSigner for RsaSigner with fn alg_name(self : RsaSigner) -> String {
  self.alg
}

///|
pub impl @mjwt.JwtSigner for RsaSigner with fn sign(
  self : RsaSigner,
  message : BytesView,
) -> FixedArray[Byte] raise @mjwt.JwtError {
  // 1. Hash
  let hash = match self.hash_len {
    32 => @crypto.sha256(message)
    48 => @hash.sha384(message)
    64 => @hash.sha512(message)
    _ => raise @mjwt.UnsupportedAlgorithm(self.alg)
  }
  let prefix = der_prefix(self.hash_len)
  // k = octet length of the RSA modulus
  let k = (self.n.bit_length() + 7) / 8

  // 2. Build EMSA-PKCS1-v1_5-ENCODE (RFC 8017 §9.2)
  // EM = 0x00 || 0x01 || PS || 0x00 || T
  // T  = DER-encoded DigestInfo
  // PS = k - len(T) - 3  (must be >= 8)
  let t_len = prefix.length() + hash.length()
  let ps_len = k - t_len - 3
  if ps_len < 8 {
    raise @mjwt.CryptoError("RSA key too short for this hash")
  }

  let em = FixedArray::make(k, b'\x00')
  em[1] = b'\x01' // block type
  for i = 0; i < ps_len; i = i + 1 {
    em[2 + i] = b'\xff'
  }
  em[2 + ps_len] = b'\x00'
  let di_off = 2 + ps_len + 1
  for i = 0; i < prefix.length(); i = i + 1 {
    em[di_off + i] = prefix[i]
  }
  for i = 0; i < hash.length(); i = i + 1 {
    em[di_off + prefix.length() + i] = hash[i]
  }

  // 3. m = bytes_to_int(EM)
  let m = unsigned_bigint_from_bytes(em.unsafe_reinterpret_as_bytes().view())

  // 4. s = m^d mod n, with RSA blinding to harden the private-key operation
  //    against timing side channels:
  //      m'    = m * r^e  (mod n)
  //      s'    = (m')^d   (mod n)
  //      s     = s' * r^-1 (mod n)
  let (r, r_inv) = blind_pair(self.n)
  let m_blind = (m * r.pow(self.e, modulus=self.n)).mod(self.n)
  let s_blind = m_blind.pow(self.d, modulus=self.n)
  let s = (s_blind * r_inv).mod(self.n)

  // 5. Output s as k bytes
  s.to_octets(length=k).to_fixedarray()
}

///|
pub extend RsaSigner with @mjwt.JwtSigner::{alg_name, sign}

// =============================================================================
//  RsaVerifier
// =============================================================================

///|
/// RSA verifier using PKCS#1 v1.5 signature scheme.
pub struct RsaVerifier {
  n : BigInt
  e : BigInt
  hash_len : Int
  alg : String
}

///|
/// Create an `RsaVerifier`.
///
/// - `n_bytes` — modulus in big-endian bytes
/// - `e_bytes` — public exponent in big-endian bytes (usually `0x010001` = 65537)
/// - `alg` — `"RS256"`, `"RS384"`, or `"RS512"`
pub fn RsaVerifier::new(
  n_bytes : BytesView,
  e_bytes : BytesView,
  alg : String,
) -> RsaVerifier raise @mjwt.JwtError {
  let (hash_len, alg_name) = match alg {
    "RS256" => (32, "RS256")
    "RS384" => (48, "RS384")
    "RS512" => (64, "RS512")
    _ => raise @mjwt.UnsupportedAlgorithm(alg)
  }
  let n = unsigned_bigint_from_bytes(n_bytes)
  if n.bit_length() < 2048 {
    raise @mjwt.CryptoError("RSA modulus must be at least 2048 bits")
  }
  { n, e: unsigned_bigint_from_bytes(e_bytes), hash_len, alg: alg_name }
}

///|
pub impl @mjwt.JwtVerifier for RsaVerifier with fn alg_name(self : RsaVerifier) -> String {
  self.alg
}

///|
pub impl @mjwt.JwtVerifier for RsaVerifier with fn verify(
  self : RsaVerifier,
  message : BytesView,
  signature : BytesView,
) -> Bool {
  let k = (self.n.bit_length() + 7) / 8
  // Reject signatures that cannot fit within the modulus early.
  if signature.length() > k {
    return false
  }
  // 1. s^e mod n
  let sig_int = unsigned_bigint_from_bytes(signature)
  let m = sig_int.pow(self.e, modulus=self.n)
  let em_decoded = m.to_octets(length=k).to_fixedarray()

  // 2. Hash the message
  let hash = match self.hash_len {
    32 => @crypto.sha256(message)
    48 => @hash.sha384(message)
    64 => @hash.sha512(message)
    _ => return false
  }
  let prefix = der_prefix(self.hash_len)
  let t_len = prefix.length() + hash.length()
  let ps_len = k - t_len - 3
  if ps_len < 8 {
    return false
  }

  // 3. Verify EM = 0x00 || 0x01 || PS || 0x00 || T  (constant-time:
  //    XOR-accumulate over every byte, no early exit, so the mismatch
  //    position is not leaked through timing)
  if em_decoded.length() != k {
    return false
  }
  let mut diff = 0
  diff = diff | em_decoded[0].to_int() // 0x00
  diff = diff | (em_decoded[1] ^ b'\x01').to_int() // 0x01
  for i = 0; i < ps_len; i = i + 1 {
    diff = diff | (em_decoded[2 + i] ^ b'\xff').to_int() // PS
  }
  diff = diff | em_decoded[2 + ps_len].to_int() // 0x00 separator
  let di_off = 2 + ps_len + 1
  for i = 0; i < prefix.length(); i = i + 1 {
    diff = diff | (em_decoded[di_off + i] ^ prefix[i]).to_int()
  }
  for i = 0; i < hash.length(); i = i + 1 {
    diff = diff | (em_decoded[di_off + prefix.length() + i] ^ hash[i]).to_int()
  }
  diff == 0
}

///|
pub extend RsaVerifier with @mjwt.JwtVerifier::{alg_name, verify}
