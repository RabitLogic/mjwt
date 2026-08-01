///|
/// # mjwt — JSON Web Token library for MoonBit
///
/// A pure-MoonBit JWT library with extensible trait-based signer architecture.
/// Supports HMAC, RSA, and ECDSA signing algorithms.  Passes **32 unit tests**
/// and is cross-validated against a Python reference implementation — HMAC
/// tokens are verified to interoperate in both directions.
///
/// > Requires MoonBit **v0.10.4+** (uses `extend` syntax for explicit trait
/// > method mounting).
///
/// ## Supported algorithms
///
/// | Algorithm | Type            | Hash       | Curve | Test |
/// |-----------|-----------------|------------|-------|------|
/// | **HS256** | HMAC symmetric  | SHA-256    | —     | ✅   |
/// | **HS384** | HMAC symmetric  | SHA-384†   | —     | ✅   |
/// | **HS512** | HMAC symmetric  | SHA-512†   | —     | ✅   |
/// | **RS256** | RSA PKCS#1 v1.5 | SHA-256    | —     | ✅   |
/// | **ES256** | ECDSA           | SHA-256    | P-256 | ✅   |
///
/// † SHA-384 / SHA-512 are self-implemented per FIPS 180-4 and verified with
///   NIST known-answer tests (empty, short, multi-block) and RFC 4231 HMAC test
///   vectors.
///
/// ## Quick start (HS256)
///
/// ```moonbit
/// let claims = JwtClaims::new()
/// claims.set_subject("user123")
///
/// let token = @mjwt.encode(claims, "my-secret")
/// let decoded = @mjwt.decode(token, "my-secret")
/// @mjwt.verify(token, "my-secret")   // true
///
/// // Inspect without verification (debugging only)
/// let raw = @mjwt.decode_without_verify(token)
/// raw.claims.get_subject()  // Some("user123")
/// ```
///
/// ## Trait-based API (extensible)
///
/// ```moonbit
/// let signer   = HmacSigner::new("HS256", "my-secret")
/// let verifier = HmacVerifier::new("HS256", "my-secret")
/// let token    = @mjwt.encode_with(signer, claims)
/// let decoded  = @mjwt.decode_with(verifier, token)
/// ```
///
/// ## Expiration check
///
/// ```moonbit
/// claims.set_expiration(1_800_000_000L)
/// claims.is_expired()    // false (year 2027 is still in the future)
/// claims.is_now_valid()  // true  (no nbf constraint)
/// ```
///
/// ## Architecture
///
/// ```
///                      ┌──────────────────────┐
///                      │   JwtSigner trait     │
///                      │   JwtVerifier trait   │
///                      └──────────┬───────────┘
///                                 │ implements
///           ┌─────────────────────┼──────────────────────┐
///           ▼                     ▼                      ▼
///    HmacSigner              RsaSigner               EcSigner
///    HmacVerifier            RsaVerifier             EcVerifier
///    (HS256/384/512)         (RS256)                 (ES256 P-256)
/// ```
///
/// | File | Responsibility |
/// |------|---------------|
/// | `mjwt.mbt` | Core: errors, traits, `JwtHeader`, `JwtClaims`, `JwtToken`, Base64URL, public API |
/// | `mjwt_hash_sha512.mbt` | SHA-384 / SHA-512 (FIPS 180-4, `@crypto.CryptoHasher`) |
/// | `mjwt_signer_hmac.mbt` | `HmacSigner` / `HmacVerifier` |
/// | `mjwt_signer_rsa.mbt` | `RsaSigner` / `RsaVerifier` |
/// | `mjwt_signer_ecdsa.mbt` | `EcSigner` / `EcVerifier` (P-256) |
/// | `examples/example_usage.mbt` | Runnable usage examples (12 test cases) |
/// | `examples/py_compare.py` | Python cross-validation script |
///
/// ## Extending
///
/// Implement `JwtSigner` / `JwtVerifier` on any type, and use `extend` to
/// expose trait methods (required since MoonBit v0.10.4):
///
/// ```moonbit nocheck
/// struct MySigner { key : Bytes }
/// impl JwtSigner for MySigner with fn alg_name(_) -> String { "HS256" }
/// impl JwtSigner for MySigner with fn sign(self, msg) -> .. { .. }
/// pub extend MySigner with JwtSigner::{alg_name, sign}
/// let token = @mjwt.encode_with(MySigner { key }, claims)
/// ```

// =============================================================================
//  Errors
// =============================================================================

///|
/// Errors that can occur during JWT encoding, decoding, or verification.
///
/// `pub(all)` so that signers living in sub-packages (`@mjwt/rsa`,
/// `@mjwt/ecdsa`) can construct the error variants they raise.
pub(all) suberror JwtError {
  /// Malformed compact serialization (not 3 dot-separated parts)
  InvalidFormat(String)
  /// Invalid Base64URL character encountered
  InvalidBase64(String)
  /// JSON parsing failure on header or claims
  InvalidJson(String)
  /// UTF-8 decoding failure
  InvalidUtf8(String)
  /// Invalid JWT header structure
  InvalidHeader(String)
  /// Signature does not match
  SignatureMismatch
  /// Requested algorithm is not supported
  UnsupportedAlgorithm(String)
  /// Cryptographic operation failed (e.g. key too short)
  CryptoError(String)
} derive(Debug, Eq)

///|
pub extend JwtError with @moonbitlang/core/debug.Debug::{to_repr}

///|
pub extend JwtError with Eq::{not_equal, equal}

///|
pub fn JwtError::to_string(self : JwtError) -> String {
  match self {
    InvalidFormat(msg) => "invalid JWT format: \{msg}"
    InvalidBase64(msg) => "invalid base64url: \{msg}"
    InvalidJson(msg) => "invalid JSON: \{msg}"
    InvalidUtf8(msg) => "invalid UTF-8: \{msg}"
    InvalidHeader(msg) => "invalid header: \{msg}"
    SignatureMismatch => "signature verification failed"
    UnsupportedAlgorithm(s) => "unsupported algorithm: \{s}"
    CryptoError(msg) => "crypto error: \{msg}"
  }
}

// =============================================================================
//  Traits — pluggable signing & verification
// =============================================================================

///|
/// Pluggable JWT signer.
///
/// Implement this on any type that holds key material.
///
/// ```moonbit nocheck
/// struct RsaSigner { n: BigUint, d: BigUint }
/// impl JwtSigner for RsaSigner with fn alg_name(_) -> String { "RS256" }
/// impl JwtSigner for RsaSigner with fn sign(self, msg) -> .. { .. }
/// ```
pub(open) trait JwtSigner {
  /// Algorithm name placed in the JWT header, e.g. `"HS256"`.
  fn alg_name(Self) -> String
  /// Produce a raw signature over `message`.
  fn sign(Self, BytesView) -> FixedArray[Byte] raise JwtError
}

///|
/// Pluggable JWT verifier.
///
/// ```moonbit nocheck
/// struct RsaVerifier { n: BigUint, e: BigUint }
/// impl JwtVerifier for RsaVerifier with fn alg_name(_) -> String { "RS256" }
/// impl JwtVerifier for RsaVerifier with fn verify(self, msg, sig) -> .. { .. }
/// ```
pub(open) trait JwtVerifier {
  /// Algorithm name, must match the signer's output.
  fn alg_name(Self) -> String
  /// Return `true` iff `signature` is valid for `message`.
  fn verify(Self, BytesView, BytesView) -> Bool
}

// =============================================================================
//  JWT Header
// =============================================================================

///|
pub(all) struct JwtHeader {
  /// Algorithm name, e.g. `"HS256"`, `"RS256"`, `"ES256"`
  alg : String
  /// Token type, always `"JWT"`
  typ : String
  /// Optional key hint
  kid : String?
}

///|
pub fn JwtHeader::new(alg : String, kid? : String = "") -> JwtHeader {
  { alg, typ: "JWT", kid: if kid == "" { None } else { Some(kid) } }
}

///|
fn JwtHeader::to_json(self : JwtHeader) -> Json {
  let map = Map([], capacity=3)
  map.set("alg", Json::string(self.alg))
  map.set("typ", Json::string(self.typ))
  match self.kid {
    Some(kid) => map.set("kid", Json::string(kid))
    None => ()
  }
  Json::object(map)
}

///|
fn JwtHeader::from_json(json : Json) -> JwtHeader raise JwtError {
  let obj = match json {
    Object(o) => o
    _ => raise InvalidHeader("expected object")
  }
  let alg_str = match obj.get("alg") {
    Some(String(s)) => s
    Some(_) => raise InvalidHeader("alg must be a string")
    None => raise InvalidHeader("missing alg")
  }
  let typ = match obj.get("typ") {
    Some(String(s)) => s
    Some(_) => raise InvalidHeader("typ must be a string")
    None => "JWT"
  }
  let kid = match obj.get("kid") {
    Some(String(s)) => Some(s)
    _ => None
  }
  { alg: alg_str, typ, kid }
}

// =============================================================================
//  JWT Claims
// =============================================================================

///|
pub(all) struct JwtClaims {
  data : Map[String, Json]
}

///|
pub fn JwtClaims::new() -> JwtClaims {
  { data: Map([], capacity=10) }
}

///|
///  Store an arbitrary key-value pair in the claims payload.
///  - `key`   – claim name, e.g. `"custom-claim"`
///  - `value` – any JSON value (`Json::string(...)`, `Json::number(...)`, etc.)
pub fn JwtClaims::set(self : JwtClaims, key : String, value : Json) -> Unit {
  self.data.set(key, value)
}

///|
///  Retrieve a previously stored claim by name.
///  Returns `None` when the key does not exist.
pub fn JwtClaims::get(self : JwtClaims, key : String) -> Json? {
  self.data.get(key)
}

///|
///  Registered claim **iss** (issuer) — identifies the principal that issued the JWT.
///  Per RFC 7519 §4.1.1.
pub fn JwtClaims::set_issuer(self : JwtClaims, iss : String) -> Unit {
  self.data.set("iss", Json::string(iss))
}

///|
///  Returns the **iss** (issuer) value, or `None` if absent.
pub fn JwtClaims::get_issuer(self : JwtClaims) -> String? {
  match self.data.get("iss") {
    Some(String(s)) => Some(s)
    _ => None
  }
}

///|
///  Registered claim **sub** (subject) — identifies the principal that is the
///  subject of the JWT.  Per RFC 7519 §4.1.2.
pub fn JwtClaims::set_subject(self : JwtClaims, sub : String) -> Unit {
  self.data.set("sub", Json::string(sub))
}

///|
///  Returns the **sub** (subject) value, or `None` if absent.
pub fn JwtClaims::get_subject(self : JwtClaims) -> String? {
  match self.data.get("sub") {
    Some(String(s)) => Some(s)
    _ => None
  }
}

///|
///  Registered claim **aud** (audience) — identifies the recipients that the JWT
///  is intended for.  Per RFC 7519 §4.1.3. A single audience is stored as a
///  JSON string.
pub fn JwtClaims::set_audience(self : JwtClaims, aud : String) -> Unit {
  self.data.set("aud", Json::string(aud))
}

///|
///  Returns the **aud** (audience) value as a string, or `None` if absent or if
///  `aud` is a JSON array (use `get_audiences` for the array form).
pub fn JwtClaims::get_audience(self : JwtClaims) -> String? {
  match self.data.get("aud") {
    Some(String(s)) => Some(s)
    _ => None
  }
}

///|
///  Sets **aud** to a JSON array of audience strings. Per RFC 7519 §4.1.3 a JWT
///  may list multiple audiences as an array.
pub fn JwtClaims::set_audiences(self : JwtClaims, auds : Array[String]) -> Unit {
  let arr : Array[Json] = []
  for s in auds {
    arr.push(Json::string(s))
  }
  self.data.set("aud", Json::array(arr))
}

///|
///  Returns **aud** as a list of strings, normalizing the JSON string-or-array
///  form per RFC 7519 §4.1.3. Returns `None` if `aud` is absent or not a string
///  / array of strings.
pub fn JwtClaims::get_audiences(self : JwtClaims) -> Array[String]? {
  match self.data.get("aud") {
    Some(String(s)) => Some([s])
    Some(Array(arr)) => {
      let out : Array[String] = []
      for v in arr {
        match v {
          String(s) => out.push(s)
          _ => return None
        }
      }
      Some(out)
    }
    _ => None
  }
}

///|
/// Parse a decimal integer string into Int64, or `None` if it is not a valid
/// in-range decimal.  Used to recover exact integer JSON numbers from `repr`.
fn parse_i64_decimal(s : String) -> Int64? {
  if s.length() == 0 {
    return None
  }
  let mut i = 0
  let mut neg = false
  if s[0] == '-' {
    neg = true
    i = 1
    if s.length() == 1 {
      return None
    }
  }
  let mut acc = 0L
  for j = i; j < s.length(); j = j + 1 {
    let c = s[j]
    if c < '0' || c > '9' {
      return None
    }
    let d = (c.to_int() - '0').to_int64()
    // overflow guard: Int64 max = 9223372036854775807
    if acc > 922_337_203_685_477_580L {
      return None
    }
    if acc == 922_337_203_685_477_580L && d > 7L {
      return None
    }
    acc = acc * 10L + d
  }
  if neg {
    Some(-acc)
  } else {
    Some(acc)
  }
}

///|
/// Extract an Int64 from a JSON number, preferring the exact decimal `repr`
/// when present (preserves precision beyond 2^53 that Double cannot hold).
fn int64_from_json(json : Json) -> Int64? {
  match json {
    Number(n, repr~) =>
      match repr {
        Some(r) =>
          match parse_i64_decimal(r) {
            Some(v) => Some(v)
            None => Some(n.to_int64())
          }
        None => Some(n.to_int64())
      }
    _ => None
  }
}

///|
///  Registered claim **exp** (expiration time) — Unix timestamp after which the
///  JWT MUST NOT be accepted.  Per RFC 7519 §4.1.4.
pub fn JwtClaims::set_expiration(self : JwtClaims, exp : Int64) -> Unit {
  self.data.set("exp", Json::number(exp.to_double(), repr=exp.to_string()))
}

///|
///  Returns the **exp** (expiration time) value, or `None` if absent.
pub fn JwtClaims::get_expiration(self : JwtClaims) -> Int64? {
  match self.data.get("exp") {
    Some(v) => int64_from_json(v)
    _ => None
  }
}

///|
///  Returns `true` when the current time (UTC) is **past** the **exp** claim.
///  Returns `false` if **exp** is not set, so it is **safe** to call on any claims.
pub fn JwtClaims::is_expired(self : JwtClaims) -> Bool {
  self.is_expired_with_leeway(0L)
}

///|
///  Same as `is_expired` but tolerates a `leeway` (in seconds) of clock skew
///  between the issuer and the verifier, per RFC 7519 §4.1.4.
///
///  A token is considered expired only once `now >= exp + leeway`, i.e. it is
///  still accepted within `leeway` seconds after the nominal expiration time.
pub fn JwtClaims::is_expired_with_leeway(
  self : JwtClaims,
  leeway : Int64,
) -> Bool {
  match self.get_expiration() {
    Some(exp) => {
      let now_s = (@env.now() / 1000).reinterpret_as_int64()
      now_s >= exp + leeway
    }
    None => false
  }
}

///|
///  Checks both **nbf** (not-before) and **exp** (expiration) against the
///  current UTC time.
///
///  Returns `true` iff:
///  - **nbf** is absent OR `now >= nbf`
///  - **exp** is absent OR `now < exp`
pub fn JwtClaims::is_now_valid(self : JwtClaims) -> Bool {
  self.is_now_valid_with_leeway(0L)
}

///|
///  Same as `is_now_valid` but tolerates a `leeway` (in seconds) of clock skew
///  between the issuer and the verifier, per RFC 7519 §4.1.4/§4.1.5.
///
///  nbf is satisfied once `now >= nbf - leeway` (accept slightly early); exp is
///  satisfied while `now < exp + leeway` (accept slightly late).
pub fn JwtClaims::is_now_valid_with_leeway(
  self : JwtClaims,
  leeway : Int64,
) -> Bool {
  let now_s = (@env.now() / 1000).reinterpret_as_int64()
  match self.get_not_before() {
    Some(nbf) => if now_s < nbf - leeway { return false }
    None => ()
  }
  match self.get_expiration() {
    Some(exp) => if now_s >= exp + leeway { return false }
    None => ()
  }
  true
}

///|
///  Registered claim **nbf** (not before) — Unix timestamp before which the JWT
///  MUST NOT be accepted.  Per RFC 7519 §4.1.5.
pub fn JwtClaims::set_not_before(self : JwtClaims, nbf : Int64) -> Unit {
  self.data.set("nbf", Json::number(nbf.to_double(), repr=nbf.to_string()))
}

///|
///  Returns the **nbf** (not before) value, or `None` if absent.
pub fn JwtClaims::get_not_before(self : JwtClaims) -> Int64? {
  match self.data.get("nbf") {
    Some(v) => int64_from_json(v)
    _ => None
  }
}

///|
///  Registered claim **iat** (issued at) — Unix timestamp when the JWT was
///  created.  Per RFC 7519 §4.1.6.
pub fn JwtClaims::set_issued_at(self : JwtClaims, iat : Int64) -> Unit {
  self.data.set("iat", Json::number(iat.to_double(), repr=iat.to_string()))
}

///|
///  Returns the **iat** (issued at) value, or `None` if absent.
pub fn JwtClaims::get_issued_at(self : JwtClaims) -> Int64? {
  match self.data.get("iat") {
    Some(v) => int64_from_json(v)
    _ => None
  }
}

///|
///  Registered claim **jti** (JWT ID) — a unique identifier for the JWT.
///  Per RFC 7519 §4.1.7.
pub fn JwtClaims::set_jwt_id(self : JwtClaims, jti : String) -> Unit {
  self.data.set("jti", Json::string(jti))
}

///|
///  Returns the **jti** (JWT ID) value, or `None` if absent.
pub fn JwtClaims::get_jwt_id(self : JwtClaims) -> String? {
  match self.data.get("jti") {
    Some(String(s)) => Some(s)
    _ => None
  }
}

///|
fn JwtClaims::to_json(self : JwtClaims) -> Json {
  Json::object(self.data)
}

///|
fn JwtClaims::from_json(json : Json) -> JwtClaims raise JwtError {
  let data = match json {
    Object(o) => o
    _ => raise InvalidJson("claims must be a JSON object")
  }
  { data, }
}

// =============================================================================
//  JWT Token (parsed representation)
// =============================================================================

///|
pub(all) struct JwtToken {
  header : JwtHeader
  claims : JwtClaims
  signature : FixedArray[Byte]
}

// =============================================================================
//  Internal helpers
// =============================================================================

///|
fn split_by_char(s : String, delim : Char) -> Array[String] {
  let result : Array[String] = []
  let mut current = StringBuilder::new()
  for ch in s {
    if ch == delim {
      result.push(current.to_string())
      current = StringBuilder::new()
    } else {
      current.write_char(ch)
    }
  }
  result.push(current.to_string())
  result
}

///|
fn base64url_encode(input : BytesView) -> String {
  let out = StringBuilder::new()
  // Note: this base64 Encoder's `padding=false` drops the final *partial
  // character* (not just the '='), so we request padding and skip '=' here.
  @base64.Encoder::new().encode_to(
    input,
    fn(c : Char) { if c != '=' { out.write_char(c) } },
    url_safe=true,
    padding=true,
  )
  out.to_string()
}

///|
fn base64url_decode(input : StringView) -> Bytes raise JwtError {
  @base64.decode(input, url_safe=true) catch {
    @base64.InvalidChar(ch) => raise InvalidBase64("invalid character: \{ch}")
  }
}

///|
fn string_to_bytes(s : String) -> Bytes {
  @encoding.encode(UTF8, s)
}

///|
fn split_token(sv : StringView) -> (String, String, String) raise JwtError {
  let parts = split_by_char(sv.to_owned(), '.')
  guard parts.length() == 3 else { raise InvalidFormat("expected 3 parts") }
  (parts[0], parts[1], parts[2])
}

///|
fn decode_json(data : Bytes) -> Json raise JwtError {
  let s = @encoding.decoder(UTF8).decode(data.view(), stream=false) catch {
    _ => raise InvalidUtf8("invalid UTF-8")
  }
  // Use the strict core JSON parser: unlike json5 it preserves the exact
  // numeric `repr` string, so Int64 claims > 2^53 survive a round-trip.
  @json.parse(s.view()) catch {
    _ => raise InvalidJson("parse error")
  }
}

// =============================================================================
//  Public API — trait-based
// =============================================================================

///|
/// Encode `claims` into a compact JWT string signed by `signer`.
///
/// ```moonbit nocheck
/// let s = HmacSigner::new("HS256", "my-secret")?
/// let t = mjwt::encode_with(s, claims)?
/// ```
pub fn[S : JwtSigner] encode_with(
  signer : S,
  claims : JwtClaims,
) -> String raise JwtError {
  let hdr = JwtHeader::new(signer.alg_name())
  let hdr_b64 = base64url_encode(
    string_to_bytes(hdr.to_json().stringify()).view(),
  )
  let pay_b64 = base64url_encode(
    string_to_bytes(claims.to_json().stringify()).view(),
  )
  let input = hdr_b64 + "." + pay_b64
  let sig = signer.sign(string_to_bytes(input).view())
  input + "." + base64url_encode(sig.unsafe_reinterpret_as_bytes().view())
}

///|
/// Verify and decode a compact JWT string using `verifier`.
///
/// ```moonbit nocheck
/// let v = HmacVerifier::new("HS256", "my-secret")?
/// let tok = mjwt::decode_with(v, token)?
/// ```
pub fn[V : JwtVerifier] decode_with(
  verifier : V,
  sv : StringView,
) -> JwtToken raise JwtError {
  let (hdr_b64, pay_b64, sig_b64) = split_token(sv)
  let hdr = JwtHeader::from_json(decode_json(base64url_decode(hdr_b64)))
  // Reject tokens whose header `alg` does not match the verifier's algorithm.
  // This prevents algorithm-confusion / downgrade attacks (RFC 7515 §4.1.1).
  if hdr.alg != verifier.alg_name() {
    raise UnsupportedAlgorithm(hdr.alg)
  }
  let claims = JwtClaims::from_json(decode_json(base64url_decode(pay_b64)))
  let input = string_to_bytes(hdr_b64 + "." + pay_b64)
  let sig = base64url_decode(sig_b64)
  if !verifier.verify(input.view(), sig.view()) {
    raise SignatureMismatch
  }
  { header: hdr, claims, signature: sig.to_fixedarray() }
}

// =============================================================================
//  Convenience wrappers (defaults to HS256)
// =============================================================================

///|
/// Encode using HMAC-SHA256.
pub fn encode(claims : JwtClaims, secret : String) -> String raise JwtError {
  encode_with(HmacSigner::new("HS256", secret) catch { e => raise e }, claims)
}

///|
/// Decode and verify HMAC-SHA256.
pub fn decode(sv : StringView, secret : String) -> JwtToken raise JwtError {
  decode_with(HmacVerifier::new("HS256", secret) catch { e => raise e }, sv)
}

///|
/// Decode **without** signature verification. Use for inspecting tokens only.
pub fn decode_without_verify(sv : StringView) -> JwtToken raise JwtError {
  let (hdr_b64, pay_b64, sig_b64) = split_token(sv)
  let hdr = JwtHeader::from_json(decode_json(base64url_decode(hdr_b64)))
  let claims = JwtClaims::from_json(decode_json(base64url_decode(pay_b64)))
  { header: hdr, claims, signature: base64url_decode(sig_b64).to_fixedarray() }
}

///|
/// Verify HMAC-SHA256 signature. Returns `true` / `false` (no panic).
pub fn verify(sv : StringView, secret : String) -> Bool {
  let v = HmacVerifier::new("HS256", secret) catch { _ => return false }
  let (hdr_b64, pay_b64, sig_b64) = split_token(sv) catch { _ => return false }
  let hdr = JwtHeader::from_json(decode_json(base64url_decode(hdr_b64))) catch {
    _ => return false
  }
  if hdr.alg != "HS256" {
    return false
  }
  let input = string_to_bytes(hdr_b64 + "." + pay_b64)
  let sig = base64url_decode(sig_b64) catch { _ => return false }
  v.verify(input.view(), sig.view())
}
