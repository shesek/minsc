# Changelog

## Unreleased

- Add support for BIP389 multi-path descriptors

  Using the BIP389 `<M;N..>` syntax: `XPUB/0/9/<0;1;2>/100`

  Or using standard Minsc arrays: `XPUB/0/9/[0,1,2]/100`

  `single_descriptors()` can be used to split multi-path descriptors into an array of single descriptors.
  For example `address(single_descriptors(wpkh(XPUB/0/<1;3;5>/100/*)).2/8)` to generate an address for `XPUB/0/5/100/8`

- Add script fragment interpolation syntax

  With a space-separated list of expressions enclosed in backticks. For example: ``` `1 2 OP_DUP OP_ADD 3 OP_EQUAL` ```

  The data types that can be interpolated are: `Script`, `Miniscript` and `Policy` (concatenated as script bytes), as well as `Number`, `Bool`, `PubKey`, `Hash`, `Duration`, `DateTime` and `Bytes` (as PUSH operations).

- Preliminary Taproot support:

  1. `tapLeaf(Script, version=0xc0) -> Hash` (compute the TapLeaf hash of the given Script)
  2. `tapBranch(Hash, Hash) -> Hash` (compute the TapBranch hash for the two given nodes)
  3. `tapTweak(PubKey internal_key, Hash|Script|Array script_tree) -> Script` (tweak the `internal_key` with the `script_tree` and return the V1 witness program SPK. `script_tree` can be the merkle root hash or any value accepted by `tapTreeRoot`)
  4. `tapTreeRoot(Script|Array tree) -> Hash` (compute the merkle root hash for the script tree. the tree can be a single Script or an Array.)

  The `+` operator can be used similarly to `tapTweak()`. For example ```H_POINT+`OP_TRUE` ``` for a script-path-only with a single script.

  Taproot descriptors (`tr()`) are not supported yet.

- Support for CheckTemplateVerify (BIP 119) with a new `ctvHash()` function. For example:
  
  ```hack
  `ctvHash([ txOut($alice_pk, 10000), txOut($bob_pk, 25000) ]) OP_CTV OP_DROP`
  ```

- Add anonymous function expressions

  With a Rust-like syntax: `|params| body` or `|params| { multi statement body }`

- Add if expressions (`if .. then .. else ..`) and statements (`if .. { ..; } else { ..; }`)

- New `Bytes` runtime data type

  Constructable using a new `0x<hex>` syntax.

  This can now be used in place of the `Hash` data type, which was removed.
  To remain compatible with the Miniscript Policy syntax for literal
  hashes, a Bytes value can be constructed without the `0x` prefix
  when it is exactly 32 or 20 bytes.

- New `Script` runtime data type and new functions for working with it:

  1. `script(Bytes) -> Script` (get a Script for the given raw opcode bytes. e.g. `script(0xb2)` for `OP_CSV`)
  2. `scriptPubkey(Descriptor|TapInfo|PubKey|Address|Script) -> Script` (get the scriptPubKey to be used in the output)
  3. `explicitScript(Descriptor) -> Script` (get the underlying witness script, before any hashing is done. AKA the redeemScript for P2SH)
  4. `bytes(Script) -> Bytes` (get the Bytes representation of the Script opcodes)

- New `String` runtime data type

- New `Transaction` runtime data type, constructable via `transaction()` from bytes or tagged arrays.

- New syntax for BTC amounts: `0.5 BTC`. Evaluates to the amount in satoshis. Supports all the [denominations in rust-bitcoin](https://docs.rs/bitcoin/latest/bitcoin/util/amount/enum.Denomination.html) (`BTC`, `mBTC`, `uBTC`, `bits`, `satoshi`/`sat`, `msat`).

- Support child derivation with a hash as the child code index using [Sapio's `hash_to_child_vec` conversion](https://learn.sapio-lang.org/ch05-01-ctv-emulator.html#how-it-works). For example: `pub6AhbqJtv4PXnPfjiFdES7acWysWeaiCQCXeyhAh9KuEMRSNhAUHq9s3Xwu85SbXmt8wAZwpRZFQqWBstcbcvVunvATag4FbmxYYjfRcXZkp/0xd47769f0eab20cd97ad3df71d7849ed21a3c8f49c87e1742635db7d30d8a191f`

- Support Bech32/Base58 addresses format directly in source code (no quoting or explicit `address()` necessary)

- New utility functions:
  1. `len(Array|Bytes|Script) -> Number`
  1. `typeof(Value) -> String`
  1. `int(Float) -> Integer`
  1. `float(Int) -> Float`
  1. `str(Value) -> String`
  1. `keys(Array) -> Array<Number>`
  2. `first(Array) -> Any`
  3. `last(Array) -> Any`
  4. `map(Array, Function) -> Array`
  5. `range(Number start, Number end) -> Array`
  6. `slice(Array, Number start, Number len) -> Array`
  7. `tail(Array) -> Array`
  7. `initial(Array) -> Array`
  8. `concat(Array, Array) -> Array`
  9. `le64(Number) -> Bytes` (encode the number as 64 bit little-endian)
  10. `pubkey(Bytes) -> PubKey` (cast a 32/33 long Bytes into a single PubKey)
  10. `transaction(Bytes|Array) -> Transaction`
  11. `repeat(Number, Function|Value) -> Array`

     The second parameter can be a value to fill the array with,
     or a function that gets called with the index to produce the value.

     For example: `repeat(3, 111) == [111, 111, 111]`, or with a function: `repeat(3, |$n| 100+$n) == [100, 101, 102]`.

- New function for conditionals: `iif(Bool condition, Any then_value, Any else_value)` -- **use `if .. then .. else ..` instead**

  Returns the `then_value` if the condition is true, or `else_value` otherwise.

  The values may be provided as thunks to be lazily-evaluated. This can be useful to avoid infinite recursion, for example: `fn S(n) = n + iif(n == 0, 0, || S(n - 1));`.

- New functions for writing Scripts:

  1. `switch(Array<(Script condition, Script body)>) -> Script`
  1. `select(Array<Script body>) -> Script`
  1. `unrollLoop(Number max_iterations, Script condition, Script body) -> Script`
  1. `unrollFor(Number max_iterations, Script body) -> Script`
  1. `rollAlt(Number) -> Script`, `pickAlt(Number) -> Script`
  1. `nToAlt(Number max_iterations)`, `nFromAlt(Number max_iterators)`
  1. Introspection helpers: `checkSameValue()`, `checkSameAsset()` and `checkSameSpk()` (Elements only)

- New `Bool` type, available as the `true` and `false` variables in the root scope

- The `Number` type can now represent floats

- New operators: `+`, `-`, `*`, `!`, `==`, `!=`, `<`, `>`, `<=` and `>=`

- New constants: `MIN_NUMBER`, `MAX_NUMBER`, `H_POINT` (point with unknown discrete logarithm for script-path-only p2tr), `LBTC`, `TLBTC`

- Add support for Signet and make it the default

- Allow using non-literal expressions as the array access index

  For example: `$list.$n` or `$list.(some complex expression)`

- Add support for negative numbers

- Support child key derivation for `Policy` and `Miniscript` without coercing them into `Descriptor`,
  as well as for `Array`s containing derivable types.

- Remove the `Duration` and `DateTime` runtime data types. Their syntax can still be used but get evaluated into a `Number`.

- Allow overriding the `BLOCK_INTERVAL` used for `heightwise` durations

  For example, `BLOCK_INTERVAL=60` to make `heightwise 1 day` resolve as 1440 on Elements rather than 144.

## 0.2.0 - 2020-11-27

- Ported from sipa-miniscript to rust-miniscript (#1)

- New native data types: `PubKey`, `Hash`, `Policy`, `Miniscript`, `Descriptor`, `Address` and `Network` (#2)

- New functions: `miniscript()`, `wsh()`, `wpkh()`, `sh()` and `address()` (#2)

- New `/` child derivation operator

- The playground was updated to support descriptors and address generation

## 0.1.0 - 2020-07-28

Initial release! 💥
