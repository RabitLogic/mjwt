///|
/// HMAC-based signer & verifier for JWT.
///
/// Uses MoonBit's `@crypto.hmac` internally.  HS384 and HS512 use the
/// self-implemented `Sha384` / `Sha512` hashers (see `mjwt_hash_sha512.mbt`)
/// which are verified with NIST known-answer tests and RFC 4231 vectors.
///
/// # Supported algorithms
///
/// | Algorithm | Hash    | Test vectors          |
/// |-----------|---------|-----------------------|
/// | HS256     | SHA-256 | ✅ RFC 4231 Test Case 2 |
/// | HS384     | SHA-384 | ✅ RFC 4231 Test Case 2 |
/// | HS512     | SHA-512 | ✅ RFC 4231 Test Case 2 |
///
/// # Panics
/// None — errors are returned via `raise JwtError`.
///
/// # Example
///
/// ```moonbit
/// let s = HmacSigner::new("HS256", "my-secret")?
/// let v = HmacVerifier::new("HS256", "my-secret")?
/// let token = @mjwt.encode_with(s, my_claims)?
/// let decoded = @mjwt.decode_with(v, token)?
/// ```

// =============================================================================
//  HmacSigner
// =============================================================================

///|
/// Symmetric HMAC signer.  The same secret is used for both signing and
/// verification.
pub struct HmacSigner {
  alg_name : String
  key : Bytes
}

///|
/// Create an `HmacSigner`.
///
/// # Parameters
/// - `alg`   — `"HS256"`, `"HS384"`, or `"HS512"`
/// - `key`   — shared secret
///
/// # Errors
/// `UnsupportedAlgorithm` when `alg` is not recognised.
pub fn HmacSigner::new(
  alg : String,
  key : StringView,
) -> HmacSigner raise JwtError {
  let name = match alg {
    "HS256" | "HS384" | "HS512" => alg
    _ => raise UnsupportedAlgorithm(alg)
  }
  { alg_name: name, key: string_to_bytes(key.to_owned()) }
}

///|
pub impl JwtSigner for HmacSigner with fn alg_name(self : HmacSigner) -> String {
  self.alg_name
}

///|
pub impl JwtSigner for HmacSigner with fn sign(
  self : HmacSigner,
  message : BytesView,
) -> FixedArray[Byte] raise JwtError {
  match self.alg_name {
    "HS256" => @crypto.hmac(@crypto.SHA256::new(), self.key.view(), message)
    "HS384" => @crypto.hmac(Sha384::new(), self.key.view(), message)
    "HS512" => @crypto.hmac(Sha512::new(), self.key.view(), message)
    _ => raise UnsupportedAlgorithm(self.alg_name)
  }
}

// =============================================================================
//  HmacVerifier
// =============================================================================

///|
/// Symmetric HMAC verifier.
pub struct HmacVerifier {
  alg_name : String
  key : Bytes
}

///|
/// Create an `HmacVerifier`.
pub fn HmacVerifier::new(
  alg : String,
  key : StringView,
) -> HmacVerifier raise JwtError {
  let name = match alg {
    "HS256" | "HS384" | "HS512" => alg
    _ => raise UnsupportedAlgorithm(alg)
  }
  { alg_name: name, key: string_to_bytes(key.to_owned()) }
}

///|
pub impl JwtVerifier for HmacVerifier with fn alg_name(self : HmacVerifier) -> String {
  self.alg_name
}

///|
pub impl JwtVerifier for HmacVerifier with fn verify(
  self : HmacVerifier,
  message : BytesView,
  signature : BytesView,
) -> Bool {
  let expected = match self.alg_name {
    "HS256" => @crypto.hmac(@crypto.SHA256::new(), self.key.view(), message)
    "HS384" => @crypto.hmac(Sha384::new(), self.key.view(), message)
    "HS512" => @crypto.hmac(Sha512::new(), self.key.view(), message)
    _ => return false
  }
  if signature.length() != expected.length() {
    return false
  }
  for i = 0; i < signature.length(); i = i + 1 {
    if signature[i] != expected[i] {
      return false
    }
  }
  true
}
