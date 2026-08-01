// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html
//
// To add a dependency, run this command in your terminal:
//   moon add moonbitlang/x
//
// Or manually declare it in `import`, for example:
// import {
//   "moonbitlang/x@0.4.6",
// }

name = "RabitLogic/mjwt"

version = "0.3.0"

readme = "README.mbt.md"

repository = "https://github.com/RabitLogic/mjwt"

license = "MIT"

keywords = [ "jwt", "json-web-token", "crypto", "hmac", "rsa", "ecdsa" ]

preferred_target = "wasm-gc"

description = "A JWT (JSON Web Token) library for MoonBit with extensible trait-based signers"

import {
  "moonbitlang/x@0.4.46",
}
