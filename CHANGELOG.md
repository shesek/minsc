# Changelog

## Unreleased

- Add script fragment interpolation syntax

  With a space-separated list of expressions enclosed in backticks. For example: ``` `1 2 OP_DUP OP_ADD 3 OP_EQUAL` ```

  The data types that can be interpolated are: Scripts, Descriptor, Miniscript and Policy (concatenated as script bytes), as well as Number, PubKey, Hash, Duration, DateTime and Bytes (as PUSH operations).

- Preliminary Taproot support:

  1. `tapLeaf(Script, version=0xc0) -> Hash` (compute the TapLeaf hash of the given Script)
  2. `tapBranch(Hash, Hash) -> Hash` (compute the TapBranch hash for the two given nodes)
  3. `tapTweak(PubKey internal_key, Hash|Script|Array script_tree) -> Script` (tweak the `internal_key` with the `script_tree` and return the V1 witness program SPK. `script_tree` can be the merkle root hash or any value accepted by `tapTreeRoot`)
  4. `tapTreeRoot(Script|Array tree) -> Hash` (compute the merkle root hash for the script tree. the tree can be a single Script or an Array.)

  The `+` operator can be used similarly to `tapTweak()`. For example ```H_POINT+`OP_TRUE` ``` for a script-path-only with a single script.

  Taproot descriptors (`tr()`) are not supported yet.

- Add anonymous function expressions

  With a Rust-like syntax: `|params| body` or `|params| { multi statement body }`

- Add new `Bytes` runtime data type

  Constructable using a new `0x<hex>` expression syntax.

  This can now be used in place of the `Hash` data type, which was removed.
  To remain compatible with the Miniscript Policy syntax for literal
  hashes, a Bytes value can be constructed without the `0x` prefix
  when it is exactly 32 or 20 bytes.

- New `Script` runtime data type and new functions for working with it:

  1. `rawscript(Bytes) -> Script` (get a Script for the given raw opcode bytes. e.g. `rawscript(0xb2)` for `OP_CSV`)
  2. `script_pubkey(Descriptor) -> Script` (get the scriptPubKey to be used in the output)
  3. `explicit_script(Descriptor) -> Script` (get the underlying witness script, before any hashing is done. AKA the `redeemScript` for P2SH)
  4. `bytes(Script) -> Bytes` (get the Bytes representation of the Script opcodes)

  The `script_*` functions also accept types that can be casted into Descriptors as their argument (Policy, Miniscript and PubKey).

- New utility functions:
  1. `len(Array|Bytes|Script) -> Number`
  2. `first(Array) -> Any`
  3. `last(Array) -> Any`
  4. `map(Array, Function) -> Array`
  5. `range(Number start, Number end) -> Array`
  6. `slice(Array, Number start, Number len) -> Array`
  7. `tail(Array) -> Array`
  8. `concat(Array, Array) -> Array`
  9. `le64(Number) -> Bytes` (encode the number as 64 bit little-endian)
  10. `repeat(Number, Function|Value) -> Array`

     The second parameter can be a value to fill the array with,
     or a function that gets called with the index to produce the value.

     For example: `repeat(3, 111) == [111, 111, 111]`, or with a function: `repeat(3, |$n| 100+$n) == [100, 101, 102]`.

- New function for conditionals: `iif(Bool condition, Any then_value, Any else_value)`

  Returns the `then_value` if the condition is true, or `else_value` otherwise.

  The values may be provided as thunks to be lazily-evaluated. This can be useful to avoid infinite recursion, for example: `fn S(n) = n + iif(n == 0, 0, || S(n - 1));`.

- New functions for writing Scripts:

  1. `switch(Array<Script>) -> Script`
  2. `unrollLoop(Number max_iterations, Script condition, Script body) -> Script`
  3. `rollFromAltStack(Number) -> Script`
  4. `pickFromAltStack(Number) -> Script`
  4. Introspection helpers: `checkSameValue()`, `checkSameAsset()` and `checkSameSpk()` (Elements only)

- New `Bool` type, available as the `true` and `false` variables in the root scope

- New operators: `+`, `-`, `!`, `==`, `!=`, `<`, `>`, `<=` and `>=`

- New constants: `MIN_NUMBER`, `MAX_NUMBER`

- Add support for multi-line `/* .. */` comments

- Allow using non-literal expressions as the array access index

  For example: `$list.$n` or `$list.(some complex expression)`

- Add support for negative numbers

- Support child key derivation for `Policy` and `Miniscript` without coercing them into `Descriptor`,
  as well as for `Array`s containing derivable types.

- Remove the `Duration` and `DateTime` runtime data types. They can still be used but get evaluated into a `Number`.

## 0.2.0 - 2020-11-27

- Ported from sipa-miniscript to rust-miniscript (#1)

- New native data types: `PubKey`, `Hash`, `Policy`, `Miniscript`, `Descriptor`, `Address` and `Network` (#2)

- New functions: `miniscript()`, `wsh()`, `wpkh()`, `sh()` and `address()` (#2)

- New `/` child derivation operator

- The playground was updated to support descriptors and address generation

## 0.1.0 - 2020-07-28

Initial release! 💥
