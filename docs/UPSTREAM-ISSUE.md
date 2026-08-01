**Title:** `BigInt::from_octets` produces a non-canonical zero for all-zero input on the native backend (breaks `==`, `<`, `to_string`)

**Environment**
- MoonBit version: `0.1.20260729`
- Affected backend: **native** (`bigint_nonjs.mbt`). The JS/wasm backend
  (`bigint_js.mbt`) parses via `parse_bigint(…, base=16)` and is unaffected.

**Summary**
On the native backend, `BigInt::from_octets` returns a **non-canonical zero**
when the input byte string is all zeros: the result keeps `len > 0` while every
limb is `0`. Because `Eq` / `Compare` compare `len` first, this value never
equals the canonical `0N` (`len == 0`), and `to_string` crashes.

This is a **security-relevant** footgun: cryptographic code that rejects zero
scalars/signatures (e.g. `r == 0`, `s == 0`, `d == 0` checks in ECDSA) silently
fails to reject, since the byte-derived zero compares unequal to the canonical
`0N`.

**Expected vs actual**

| Operation | Expected | Actual |
|---|---|---|
| `from_octets(b"\x00\x00\x00\x00") == 0N` | `true` | `false` |
| `from_octets(b"\x00\x00\x00\x00").to_string()` | `"0"` | panics (`PanicError`) |
| `from_octets(b"\x00\x00\x00\x00") < 1N` | `true` | `false` (compares by `len`: 3 vs 1) |

**Steps to reproduce** (native target)

```moonbit
let z = @bigint.BigInt::from_octets(b"\x00\x00\x00\x00")
println(z.to_string()) // PanicError (SIGABRT)
println(z == 0N)       // false — should be true
```

**Root cause** (`bigint_nonjs.mbt`, `BigInt::from_octets`)
After building `limbs`, the "top limb is zero" branch sets
`len = max(1, limbs_len - 1)`. For an all-zero input this leaves
`len = limbs_len - 1 > 0` with all-zero limbs, so the value is a non-canonical
zero. `Eq` / `Compare` compare `len` before the limbs, and `to_string` indexes
`v[v_idx - 1]` assuming a non-zero top limb.

**Proposed fix**
Return the canonical `zero` when every limb is zero. The check can be folded
into the existing limb-building loop so the all-zero case is handled without an
extra pass over the built array:

```moonbit
// in BigInt::from_octets, after building `limbs`:
let mut nonzero = false
for i = 0; i < limbs_len; i = i + 1 {
  if limbs[i] != 0 { nonzero = true; break }
}
if not nonzero { return zero }
```

**Severity**
Low-to-medium. Not directly exploitable, but it silently disables zero-value
guard checks (e.g. ECDSA `r`/`s`/`d` rejection) in code that converts byte
strings to `BigInt`, which can turn a "reject invalid input" path into an
accepted one.

**Workaround (affected users)**
Normalize all-zero byte strings to the canonical `0N` around `from_octets`.
`RabitLogic/mjwt` does this in a private `bi_from_octets` helper in both the
`ecdsa/` and `rsa/` packages (see `SECURITY.md`).
