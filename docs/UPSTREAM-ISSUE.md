# Upstream issue: MoonBit core `BigInt::from_octets` zero bug

File this at <https://github.com/moonbitlang/core/issues/new>. Paste the body
below verbatim. This documents a security-relevant core-library bug that `mjwt`
works around (see `SECURITY.md` → "Known MoonBit core bug (worked around)").

---

**Title:** `BigInt::from_octets` returns non-canonical zero for all-zero input (breaks `==`, `<`, `to_string`)

**Environment**
- MoonBit version: `0.1.20260729`

**Summary**
`BigInt::from_octets` returns a **non-canonical zero** when given an all-zero
byte string: the result has `len > 0` with all-zero limbs. This breaks `==`,
`<`, and `to_string` on that value, which is a **security-relevant** footgun:
crypto code that rejects zero scalars/signatures (e.g. `r == 0`, `s == 0`,
`d == 0` checks in ECDSA) silently fails because the byte-derived zero compares
unequal to the canonical `0N`.

**Steps to reproduce**
```moonbit
let z = @bigint.BigInt::from_octets(b"\x00\x00\x00\x00")
println(z.to_string()) // PanicError (SIGABRT)
println(z == 0N)       // false — should be true
```

**Root cause** (`bigint_nonjs.mbt`, `BigInt::from_octets`)
For all-zero input the "top limb is zero" branch runs and sets
`len = max(1, limbs_len - 1)`, leaving `len > 0` while all limbs are `0`.
`Eq` / `Compare` compare `len` first, so this value never equals the canonical
`0N` (`len == 0`), and `to_string` reads `v[v_idx - 1] == 0` then underflows.

**Proposed fix**
Return the canonical `zero` when all limbs are zero, e.g. an early return in
`from_octets`:

```moonbit
// after building `limbs`:
let mut all_zero = true
for i = 0; i < limbs_len; i = i + 1 {
  if limbs[i] != 0 { all_zero = false; break }
}
if all_zero { return zero }
```

**Impact**
Any code converting byte strings to `BigInt` where the input may legitimately
be all zeros (hash outputs, scalar/signature parsing, key material). In
`RabitLogic/mjwt` this would have silently defeated the `r=0` / `s=0` / `d=0`
ECDSA rejection checks; we currently work around it with a normalizing wrapper
(`bi_from_octets`) in both `ecdsa/` and `rsa/` packages.
