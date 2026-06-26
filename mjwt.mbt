///|
/// mjwt - A JWT (JSON Web Token) library for MoonBit
///
/// Supports HS256 (HMAC-SHA256) signing and verification.

// ===== Error Type =====

///|
/// Error type for JWT operations
pub suberror JwtError {
  InvalidFormat(String)
  InvalidBase64(String)
  InvalidJson(String)
  InvalidUtf8(String)
  InvalidHeader(String)
  SignatureMismatch
} derive(Debug, Eq)

///|
pub fn JwtError::to_string(self : JwtError) -> String {
  match self {
    InvalidFormat(msg) => "invalid JWT format: \{msg}"
    InvalidBase64(msg) => "invalid base64url: \{msg}"
    InvalidJson(msg) => "invalid JSON: \{msg}"
    InvalidUtf8(msg) => "invalid UTF-8: \{msg}"
    InvalidHeader(msg) => "invalid header: \{msg}"
    SignatureMismatch => "signature verification failed"
  }
}

// ===== Algorithm =====

///|
/// Supported JWT algorithms
pub(all) enum Algorithm {
  HS256
} derive(Eq, Debug)

///|
fn Algorithm::to_string(self : Algorithm) -> String {
  match self {
    HS256 => "HS256"
  }
}

// ===== JWT Header =====

///|
/// JWT Header containing algorithm and type information
pub(all) struct JwtHeader {
  alg : Algorithm
  typ : String
  kid : String?
}

///|
/// Create a new JWT Header
pub fn JwtHeader::new(alg : Algorithm, kid? : String = "") -> JwtHeader {
  { alg, typ: "JWT", kid: if kid == "" { None } else { Some(kid) } }
}

///|
fn JwtHeader::to_json(self : JwtHeader) -> Json {
  let map = Map([], capacity=3)
  map.set("alg", Json::string(self.alg.to_string()))
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
  let alg = match alg_str {
    "HS256" => HS256
    _ => raise InvalidHeader("unsupported algorithm: \{alg_str}")
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
  { alg, typ, kid }
}

// ===== JWT Claims =====

///|
/// JWT Claims payload.
pub(all) struct JwtClaims {
  data : Map[String, Json]
}

///|
/// Create a new empty JWT Claims
pub fn JwtClaims::new() -> JwtClaims {
  { data: Map([], capacity=10) }
}

///|
/// Set a custom claim
pub fn JwtClaims::set(self : JwtClaims, key : String, value : Json) -> Unit {
  self.data.set(key, value)
}

///|
/// Get a claim value
pub fn JwtClaims::get(self : JwtClaims, key : String) -> Json? {
  self.data.get(key)
}

///|
/// Set the issuer (iss) claim
pub fn JwtClaims::set_iss(self : JwtClaims, iss : String) -> Unit {
  self.data.set("iss", Json::string(iss))
}

///|
/// Get the issuer (iss) claim
pub fn JwtClaims::get_iss(self : JwtClaims) -> String? {
  match self.data.get("iss") {
    Some(String(s)) => Some(s)
    _ => None
  }
}

///|
/// Set the subject (sub) claim
pub fn JwtClaims::set_sub(self : JwtClaims, sub : String) -> Unit {
  self.data.set("sub", Json::string(sub))
}

///|
/// Get the subject (sub) claim
pub fn JwtClaims::get_sub(self : JwtClaims) -> String? {
  match self.data.get("sub") {
    Some(String(s)) => Some(s)
    _ => None
  }
}

///|
/// Set the audience (aud) claim
pub fn JwtClaims::set_aud(self : JwtClaims, aud : String) -> Unit {
  self.data.set("aud", Json::string(aud))
}

///|
/// Get the audience (aud) claim
pub fn JwtClaims::get_aud(self : JwtClaims) -> String? {
  match self.data.get("aud") {
    Some(String(s)) => Some(s)
    _ => None
  }
}

///|
/// Set the expiration time (exp) claim as a Unix timestamp
pub fn JwtClaims::set_exp(self : JwtClaims, exp : Int64) -> Unit {
  self.data.set("exp", Json::number(exp.to_double()))
}

///|
/// Get the expiration time (exp) claim
pub fn JwtClaims::get_exp(self : JwtClaims) -> Int64? {
  match self.data.get("exp") {
    Some(Number(n, ..)) => Some(n.to_int64())
    _ => None
  }
}

///|
/// Set the not before (nbf) claim as a Unix timestamp
pub fn JwtClaims::set_nbf(self : JwtClaims, nbf : Int64) -> Unit {
  self.data.set("nbf", Json::number(nbf.to_double()))
}

///|
/// Get the not before (nbf) claim
pub fn JwtClaims::get_nbf(self : JwtClaims) -> Int64? {
  match self.data.get("nbf") {
    Some(Number(n, ..)) => Some(n.to_int64())
    _ => None
  }
}

///|
/// Set the issued at (iat) claim as a Unix timestamp
pub fn JwtClaims::set_iat(self : JwtClaims, iat : Int64) -> Unit {
  self.data.set("iat", Json::number(iat.to_double()))
}

///|
/// Get the issued at (iat) claim
pub fn JwtClaims::get_iat(self : JwtClaims) -> Int64? {
  match self.data.get("iat") {
    Some(Number(n, ..)) => Some(n.to_int64())
    _ => None
  }
}

///|
/// Set the JWT ID (jti) claim
pub fn JwtClaims::set_jti(self : JwtClaims, jti : String) -> Unit {
  self.data.set("jti", Json::string(jti))
}

///|
/// Get the JWT ID (jti) claim
pub fn JwtClaims::get_jti(self : JwtClaims) -> String? {
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
fn JwtClaims::from_json(json : Json) -> JwtClaims {
  let data = match json {
    Object(o) => o
    _ => Map([], capacity=0)
  }
  { data: data }
}

// ===== JWT Token =====

///|
/// A parsed JWT token
pub(all) struct JwtToken {
  header : JwtHeader
  claims : JwtClaims
  signature : FixedArray[Byte]
}

// ===== Internal helpers =====

///|
/// Split a string by a delimiter character, returning the parts
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
/// Base64URL encode without padding (= characters)
///
/// Uses the Base64 Encoder with padding, then strips trailing '=' chars.
/// This is correct per JWT RFC 7515.
fn base64url_encode(input : BytesView) -> String {
  let raw = @base64.encode(input, url_safe=true)
  // Strip trailing '=' padding characters
  let chars = raw.to_array()
  let mut trim_end = chars.length()
  for i = chars.length() - 1; i >= 0; i = i - 1 {
    if chars[i] == '=' {
      trim_end = i
    } else {
      break
    }
  }
  // Build string without padding
  let result = StringBuilder::new()
  for i = 0; i < trim_end; i = i + 1 {
    result.write_char(chars[i])
  }
  result.to_string()
}

///|
/// Base64URL decode (handles missing padding)
fn base64url_decode(input : StringView) -> Bytes raise JwtError {
  @base64.decode(input, url_safe=true) catch {
    @base64.InvalidChar(ch) => raise InvalidBase64("invalid character: \{ch}")
  }
}

///|
/// Sign a message with HMAC-SHA256
fn hmac_sha256(key : BytesView, message : BytesView) -> FixedArray[Byte] {
  let sha256 = @crypto.SHA256::new()
  @crypto.hmac(sha256, key, message)
}

///|
/// Convert a string to UTF-8 bytes
fn string_to_bytes(s : String) -> Bytes {
  @encoding.encode(UTF8, s)
}

///|
fn split_token(token_str : StringView) -> (String, String, String) raise JwtError {
  let s = token_str.to_owned()
  let parts = split_by_char(s, '.')
  guard parts.length() == 3 else { raise InvalidFormat("expected 3 parts") }
  (parts[0], parts[1], parts[2])
}

///|
fn bytes_equal(a : Bytes, b : FixedArray[Byte]) -> Bool {
  if a.length() != b.length() { return false }
  for i = 0; i < a.length(); i = i + 1 {
    if a[i] != b[i] { return false }
  }
  true
}

///|
fn decode_json_str(data : Bytes) -> (String, Json) raise JwtError {
  let str = @encoding.decoder(UTF8).decode(data.view(), stream=false) catch {
    _ => raise InvalidUtf8("invalid UTF-8")
  }
  let json = @json5.parse(str) catch {
    _ => raise InvalidJson("parse error")
  }
  (str, json)
}

// ===== Public API =====

///|
/// Encode and sign a JWT token
///
/// Parameters:
/// - `alg`: The signing algorithm (e.g., `HS256`)
/// - `claims`: The JWT claims payload
/// - `secret`: The secret key for HMAC signing
///
/// Returns the compact JWT string in the format `header.payload.signature`
pub fn encode(alg : Algorithm, claims : JwtClaims, secret : String) -> String {
  let header = JwtHeader::new(alg)
  let header_json = header.to_json()
  let claims_json = claims.to_json()

  let header_b64 = base64url_encode(string_to_bytes(header_json.stringify()).view())
  let claims_b64 = base64url_encode(string_to_bytes(claims_json.stringify()).view())

  let input = header_b64 + "." + claims_b64
  let input_bytes = string_to_bytes(input)
  let secret_bytes = string_to_bytes(secret)
  let sig = hmac_sha256(secret_bytes.view(), input_bytes.view())
  let sig_b64 = base64url_encode(sig.unsafe_reinterpret_as_bytes().view())

  input + "." + sig_b64
}

///|
/// Verify and decode a JWT token
///
/// Parameters:
/// - `token_str`: The compact JWT string
/// - `secret`: The secret key for HMAC verification
///
/// Returns the decoded `JwtToken` if the signature is valid
pub fn decode(token_str : StringView, secret : String) -> JwtToken raise JwtError {
  let (header_b64, claims_b64, sig_b64) = split_token(token_str)

  // Verify signature
  let input = header_b64 + "." + claims_b64
  let input_bytes = string_to_bytes(input)
  let secret_bytes = string_to_bytes(secret)
  let expected_sig = hmac_sha256(secret_bytes.view(), input_bytes.view())

  let decoded_sig = base64url_decode(sig_b64)
  if !bytes_equal(decoded_sig, expected_sig) {
    raise SignatureMismatch
  }

  // Decode header
  let header_bytes = base64url_decode(header_b64)
  let (_, header_json) = decode_json_str(header_bytes)
  let header = JwtHeader::from_json(header_json)

  // Decode claims
  let claims_bytes = base64url_decode(claims_b64)
  let (_, claims_json) = decode_json_str(claims_bytes)
  let claims = JwtClaims::from_json(claims_json)

  { header, claims, signature: expected_sig }
}

///|
/// Decode a JWT token without verifying the signature
///
/// WARNING: This does NOT verify the token's authenticity.
/// Only use for inspecting token contents.
pub fn decode_without_verify(token_str : StringView) -> JwtToken raise JwtError {
  let (header_b64, claims_b64, sig_b64) = split_token(token_str)

  // Decode header
  let header_bytes = base64url_decode(header_b64)
  let (_, header_json) = decode_json_str(header_bytes)
  let header = JwtHeader::from_json(header_json)

  // Decode claims
  let claims_bytes = base64url_decode(claims_b64)
  let (_, claims_json) = decode_json_str(claims_bytes)
  let claims = JwtClaims::from_json(claims_json)

  // Decode signature
  let sig_bytes = base64url_decode(sig_b64)
  let sig_array = sig_bytes.to_fixedarray()

  { header, claims, signature: sig_array }
}

///|
/// Verify a JWT token's signature
///
/// Returns `true` if the signature is valid, `false` otherwise
pub fn verify(token_str : StringView, secret : String) -> Bool {
  let parts = split_token(token_str) catch { _ => return false }
  let (header_b64, claims_b64, sig_b64) = parts

  let input = header_b64 + "." + claims_b64
  let input_bytes = string_to_bytes(input)
  let secret_bytes = string_to_bytes(secret)
  let expected_sig = hmac_sha256(secret_bytes.view(), input_bytes.view())

  let decoded_sig = base64url_decode(sig_b64) catch { _ => return false }

  bytes_equal(decoded_sig, expected_sig)
}
