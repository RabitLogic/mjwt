///|
/// RSA signer & verifier for JWT (PKCS#1 v1.5).
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
/// let token = mjwt::encode_with(signer, claims)?
/// ```

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
/// - `hash_len` — output length of the hash (32=SHA256, 48=SHA384, 64=SHA512)
pub struct RsaSigner {
  n : BigInt
  d : BigInt
  hash_len : Int
  alg : String
}

///|
/// Create an `RsaSigner`.
///
/// - `n_bytes` — modulus in big-endian bytes
/// - `d_bytes` — private exponent in big-endian bytes
/// - `alg` — `"RS256"`, `"RS384"`, or `"RS512"`
pub fn RsaSigner::new(
  n_bytes : BytesView,
  d_bytes : BytesView,
  alg : String,
) -> RsaSigner raise JwtError {
  let (hash_len, alg_name) = match alg {
    "RS256" => (32, "RS256")
    "RS384" => (48, "RS384")
    "RS512" => (64, "RS512")
    _ => raise UnsupportedAlgorithm(alg)
  }
  let n = BigInt::from_octets(n_bytes)
  let d = BigInt::from_octets(d_bytes)
  { n, d, hash_len, alg: alg_name }
}

///|
pub impl JwtSigner for RsaSigner with fn alg_name(self : RsaSigner) -> String {
  self.alg
}

///|
pub impl JwtSigner for RsaSigner with fn sign(
  self : RsaSigner,
  message : BytesView,
) -> FixedArray[Byte] raise JwtError {
  // 1. Hash
  let hash = match self.hash_len {
    32 => @crypto.sha256(message)
    48 => sha384(message)
    64 => sha512(message)
    _ => raise UnsupportedAlgorithm(self.alg)
  }
  let prefix = der_prefix(self.hash_len)
  let em_len = self.n.bit_length().to_uint64().to_int() // ceil(bit_len/8) = byte_len
  let k = (em_len + 7) / 8

  // 2. Build EMSA-PKCS1-v1_5-ENCODE
  // EM = 0x00 || 0x01 || PS || 0x00 || T
  // PS = k - len(T) - 3 bytes of 0xff
  let t_len = 2 + 8 + prefix.length() + hash.length()
  let ps_len = k - t_len - 3
  if ps_len < 8 {
    raise CryptoError("RSA key too short for this hash")
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
  let m = BigInt::from_octets(em.unsafe_reinterpret_as_bytes().view())

  // 4. s = m^d mod n
  let s = m.pow(self.d, modulus=self.n)

  // 5. Output s as k bytes
  s.to_octets(length=k).to_fixedarray()
}

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
) -> RsaVerifier raise JwtError {
  let (hash_len, alg_name) = match alg {
    "RS256" => (32, "RS256")
    "RS384" => (48, "RS384")
    "RS512" => (64, "RS512")
    _ => raise UnsupportedAlgorithm(alg)
  }
  {
    n: BigInt::from_octets(n_bytes),
    e: BigInt::from_octets(e_bytes),
    hash_len,
    alg: alg_name,
  }
}

///|
pub impl JwtVerifier for RsaVerifier with fn alg_name(self : RsaVerifier) -> String {
  self.alg
}

///|
pub impl JwtVerifier for RsaVerifier with fn verify(
  self : RsaVerifier,
  message : BytesView,
  signature : BytesView,
) -> Bool {
  // 1. s^e mod n
  let sig_int = BigInt::from_octets(signature)
  let m = sig_int.pow(self.e, modulus=self.n)
  let k = (self.n.bit_length() + 7) / 8
  let em_decoded = m.to_octets(length=k).to_fixedarray()

  // 2. Hash the message
  let hash = match self.hash_len {
    32 => @crypto.sha256(message)
    48 => sha384(message)
    64 => sha512(message)
    _ => return false
  }
  let prefix = der_prefix(self.hash_len)
  let t_len = 2 + 8 + prefix.length() + hash.length()
  let ps_len = k - t_len - 3
  if ps_len < 8 {
    return false
  }

  // 3. Verify EM = 0x00 || 0x01 || PS || 0x00 || T
  if em_decoded.length() != k {
    return false
  }
  if em_decoded[0] != b'\x00' || em_decoded[1] != b'\x01' {
    return false
  }
  for i = 0; i < ps_len; i = i + 1 {
    if em_decoded[2 + i] != b'\xff' {
      return false
    }
  }
  if em_decoded[2 + ps_len] != b'\x00' {
    return false
  }
  let di_off = 2 + ps_len + 1
  for i = 0; i < prefix.length(); i = i + 1 {
    if em_decoded[di_off + i] != prefix[i] {
      return false
    }
  }
  for i = 0; i < hash.length(); i = i + 1 {
    if em_decoded[di_off + prefix.length() + i] != hash[i] {
      return false
    }
  }
  true
}
