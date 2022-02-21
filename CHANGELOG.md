# Changelog

## Unreleased

- Add script fragment interpolation syntax

  With a space-separated list of expressions enclosed in backticks. For example: ``` `1 2 OP_DUP OP_ADD 3 OP_EQUAL` ```

  The data types that can be interpolated are: Scripts, Descriptor, Miniscript and Policy (concatenated as script bytes), as well as Number, PubKey, Hash, Duration and DateTime (as PUSH operations).

- Add anonymous function expressions

  With a Rust-like syntax: `|params| body` or `|params| { multi statement body }`

- New `Script` runtime data type and `script_pubkey()`/`script_witness()` functions

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
