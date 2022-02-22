# Changelog

## Unreleased

- Add script fragment interpolation syntax

  With a space-separated list of expressions enclosed in backticks. For example: ``` `1 2 OP_DUP OP_ADD 3 OP_EQUAL` ```

  The data types that can be interpolated are: Scripts, Descriptor, Miniscript and Policy (concatenated as script bytes), as well as Number, PubKey, Hash, Duration, DateTime and Bytes (as PUSH operations).

- Add anonymous function expressions

  With a Rust-like syntax: `|params| body` or `|params| { multi statement body }`

- Add new `Bytes` runtime data type

  Constructable using a new `0x<hex>` expression syntax.

  This can now be used in place of the `Hash` data type, which was removed.
  To remain compatible with the Miniscript Policy syntax for literal
  hashes, a Bytes value can be constructed without the `0x` prefix
  when it is exactly 32 or 20 bytes.

- New `Script` runtime data type and new functions for producing it:

  a. `rawscript(Bytes) -> Script` (get a Script for the given raw opcode bytes. e.g. `rawscript(0xb2)` for `OP_CSV`)
  a. `script_pubkey(Descriptor) -> Script` (get the scriptPubKey to be used in the output)
  b. `script_witness(Descriptor) -> Script` (get the underlying witness script, before any hashing is done. AKA the `redeemScript` for P2SH)

  The `script_*` functions also accept types that can be casted into Descriptors as their argument (Policy, Miniscript and PubKey).

- New array function: `len(Array) -> Number`

- Add support for multi-line `/* .. */` comments

- Allow using non-literal expressions as the array access index

  For example: `$list.$n` or `$list.(some complex expression)`

## 0.2.0 - 2020-11-27

- Ported from sipa-miniscript to rust-miniscript (#1)

- New native data types: `PubKey`, `Hash`, `Policy`, `Miniscript`, `Descriptor`, `Address` and `Network` (#2)

- New functions: `miniscript()`, `wsh()`, `wpkh()`, `sh()` and `address()` (#2)

- New `/` child derivation operator

- The playground was updated to support descriptors and address generation

## 0.1.0 - 2020-07-28

Initial release! 💥
