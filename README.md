[![Build Status](https://github.com/shesek/minsc/actions/workflows/rust.yml/badge.svg)](https://github.com/shesek/minsc/actions/workflows/rust.yml)
[![crates.io](https://img.shields.io/crates/v/minsc.svg)](https://crates.io/crates/minsc)
[![npm](https://img.shields.io/npm/v/minsc.svg?color=blue)](https://www.npmjs.com/package/minsc)
[![MIT license](https://img.shields.io/github/license/shesek/minsc.svg?color=yellow)](https://github.com/shesek/minsc/blob/master/LICENSE)
![Pull Requests Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)

# Minsc

### A mini scripting language for all things Bitcoin

Minsc is a high-level, domain-specific language for Bitcoin scripting that simplifies the creation and fulfillment of complex spending conditions, using an expressive pseudo-code-like syntax. It has built-in support for Descriptors, Miniscript, Script, Transactions, PSBT, Taproot, Xpubs/Xprivs, CTV, and more.

> [!NOTE]
> The documentation and playground on the [`min.sc`](https://min.sc/) website are severely outdated.
>
> To explore some of Minsc's new abilities, check out the [`min.sc/v0.3`](https://min.sc/v0.3/) playground and the following examples:
>
> #### Descriptors, Miniscript & PSBT
> - [Simple Taproot PSBT](https://min.sc/v0.3/#github=examples/taproot-psbt-simple.minsc) (P2TR key-path, BIP389 multi-path, BIP86)
> - [Simple Multisig](https://min.sc/v0.3/#github=examples/multisig-simple.minsc) (P2WSH 2-of-2)
> - [Co-signer with expiry](https://min.sc/v0.3/#github=examples/cosigner-with-expiry.minsc) (P2TR with Miniscript leaves, Green-like)
> - [Multisig 3-of-3 into 2-of-3](https://min.sc/v0.3/#github=examples/3of3-into-2of3.minsc)
> - [Hashed Timelock Contract](https://min.sc/v0.3/#github=examples/htlc.minsc) (HTLC)
> - [Recovery after a delay period](https://min.sc/v0.3/#github=examples/recovery-after-delay.minsc) (simple CSV-based, delay period since the coins last moved)
> - [Inheritance after a contest period](https://min.sc/v0.3/#github=examples/inheritance-after-contest-presigned.minsc) (2-stage using pre-signed transactions, contest delay period following the trigger tx)
>
> #### Manual & Script
> - [Manual Signing](https://min.sc/v0.3/#github=examples/manual-signing-p2wpkh.minsc) (P2WPKH without Descriptors, Miniscript or PSBT)
> - [Manual Scripting & Signing](https://min.sc/v0.3/#github=examples/manual-scripting-signing-p2wsh.minsc) (P2WSH without Descriptors, Miniscript or PSBT)
> - [Simple CTV Whitelist](https://min.sc/v0.3/#github=examples/ctv-simple.minsc) (P2TR with raw Script leaves)
> - [CTV Vault](https://min.sc/v0.3/#github=examples/ctv-vault.minsc) (WIP code)
> - [Simplest CAT](https://min.sc/v0.3/#github=examples/cat-simplest.minsc)
>
> #### Elements/Liquid Introspection
> - [Dutch Auction](https://min.sc/v0.3/#github=examples/elements-dutch-auction.minsc)
> - [Token Sale with royalty](https://min.sc/v0.3/#github=examples/elements-sale-royalty.minsc) (recursive stateful contract, WIP code)
>
> --------
> 
> To learn more, you can also check out the Minsc standard library parts implemented in Minsc:
> - [`src/stdlib/stdlib.minsc`](https://min.sc/v0.3/#github=src/stdlib/stdlib.minsc) (utilities for arrays, strings, testing and more)
> - [`src/stdlib/btc.minsc`](https://min.sc/v0.3/#github=src/stdlib/btc.minsc) (transaction utilities, `Script` loop unrolling, control structures and more)
> - [`src/stdlib/elements.minsc`](https://min.sc/v0.3/#github=src/stdlib/elements.minsc) (introspection, 64-bit arithmetic and more)

<!-- Minsc is a high-level scripting language for expressing Bitcoin Script spending conditions.
It is based on the [Miniscript](http://bitcoin.sipa.be/miniscript/) Policy language,
with additional features and syntactic sugar sprinkled on top, including variables, functions, infix notation, human-readable times and more.

Documentation & live playground are available on the website: https://min.sc 

Support development: [⛓️ on-chain or ⚡ lightning via BTCPay](https://btcpay.shesek.info/) 

## Examples

- A user and a 2FA service need to sign off, but after 90 days the user alone is enough
  ```hack
  pk(user_pk) && (pk(service_pk) || older(90 days))
  ```
  [:arrow_forward: Try it live](https://min.sc/#c=%2F%2F%20A%20user%20and%20a%202FA%20service%20need%20to%20sign%20off%2C%20but%20after%2090%20days%20the%20user%20alone%20is%20enough%0A%0Apk%28user_pk%29%20%26%26%20%28pk%28service_pk%29%20%7C%7C%20older%2890%20days%29%29)

- Traditional preimage-based HTLC
  ```hack
  $redeem = pk(A) && sha256(H);
  $refund = pk(B) && older(10);

  $redeem || $refund
  ```
  [:arrow_forward: Try it live](https://min.sc/#c=%2F%2F%20Traditional%20preimage-based%20HTLC%0A%0A%24redeem%20%3D%20pk%28A%29%20%26%26%20sha256%28H%29%3B%0A%24refund%20%3D%20pk%28B%29%20%26%26%20older%2810%29%3B%0A%0A%24redeem%20%7C%7C%20%24refund)

- Liquid-like federated pegin, with emergency recovery keys that become active after a timeout
  ```hack
  $federation = 4 of [ pk(A), pk(B), pk(C), pk(D), pk(E) ];
  $recovery = 2 of [ pk(F), pk(G), pk(I) ];
  $timeout = older(3 months);

  likely@$federation || ($timeout && $recovery)
  ```
  [:arrow_forward: Try it live](https://min.sc/#c=%2F%2F%20Liquid-like%20federated%20pegin%2C%20with%20emergency%20recovery%20keys%0A%0A%24federation%20%3D%204%20of%20%5B%20pk%28A%29%2C%20pk%28B%29%2C%20pk%28C%29%2C%20pk%28D%29%2C%20pk%28E%29%20%5D%3B%20%0A%24recovery%20%3D%202%20of%20%5B%20pk%28F%29%2C%20pk%28G%29%2C%20pk%28I%29%20%5D%3B%0A%24timeout%20%3D%20older%283%20months%29%3B%0A%0Alikely%40%24federation%20%7C%7C%20%28%24timeout%20%26%26%20%24recovery%29)

- The BOLT #3 received HTLC policy
  ```hack
  fn bolt3_htlc_received($revoke_pk, $local_pk, $remote_pk, $secret, $delay) {
    $success = pk($local_pk) && hash160($secret);
    $timeout = older($delay);

    pk($revoke_pk) || (pk($remote_pk) && ($success || $timeout))
  }

  bolt3_htlc_received(A, B, C, H1, 2 hours)
  ```
  [:arrow_forward: Try it live](https://min.sc/#c=%2F%2F%20The%20BOLT%20%233%20received%20HTLC%20policy%0A%0Afn%20bolt3_htlc_received%28%24revoke_pk%2C%20%24local_pk%2C%20%24remote_pk%2C%20%24secret%2C%20%24delay%29%20%7B%0A%20%20%24success%20%3D%20pk%28%24local_pk%29%20%26%26%20hash160%28%24secret%29%3B%0A%20%20%24timeout%20%3D%20older%28%24delay%29%3B%0A%0A%20%20pk%28%24revoke_pk%29%20%7C%7C%20%28pk%28%24remote_pk%29%20%26%26%20%28%24success%20%7C%7C%20%24timeout%29%29%0A%7D%0A%0Abolt3_htlc_received%28A%2C%20B%2C%20C%2C%20H1%2C%202%20hours%29)

- Advanced 2FA where the user has a 2-of-2 setup and the service provider is a 3-of-4 federation
  ```hack
  fn two_factor($user, $provider, $delay) =
    $user && (likely@$provider || older($delay));

  $user = pk(desktop_pk) && pk(mobile_pk);
  $providers = [ pk(A), pk(B), pk(C), pk(D) ];

  two_factor($user, 3 of $providers, 4 months)
  ```
  [:arrow_forward: Try it live](https://min.sc/#c=%2F%2F%20Two%20factor%20authentication%20with%20a%20timeout%20recovery%20clause%0Afn%20two_factor%28%24user%2C%20%24provider%2C%20%24delay%29%20%3D%20%0A%20%20%24user%20%26%26%20%28likely%40%24provider%20%7C%7C%20older%28%24delay%29%29%3B%0A%0A%2F%2F%202FA%20where%20the%20user%20has%20a%202-of-2%20setup%20and%20the%20provider%20is%20a%203-of-4%20federation%0A%0A%24user%20%3D%20pk%28desktop_pk%29%20%26%26%20pk%28mobile_pk%29%3B%0A%24providers%20%3D%20%5B%20pk%28A%29%2C%20pk%28B%29%2C%20pk%28C%29%2C%20pk%28D%29%20%5D%3B%0A%0Atwo_factor%28%24user%2C%203%20of%20%24providers%2C%204%20months%29)

More examples are available on https://min.sc.-->

## Local installation

[Install Rust](https://rustup.rs/) and:

```bash
$ cargo install minsc

# Execute a minsc file
$ minsc examples/htlc.minsc

# Execute from stdin
$ echo 'pk(d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c) && older(1 week)' | minsc -

# Dump AST
$ minsc examples/htlc.minsc --ast
```

Using the Rust API:
```rust
use minsc::{parse, eval};

let code = "pk(d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c) && older(1 week)";
let res = eval(&code).unwrap(); // a minsc::Value
println!("{}", res);

// Extract the miniscript::Policy
let policy = res.into_policy().unwrap();
```

Full documentation for the Rust API is [available here](https://docs.rs/minsc/).

## JavaScript WASM package

Install with `npm install minsc` and:

```js
import { run } from 'minsc'

const policy = run('pk(A) && older(1 week)')
const miniscript = run('miniscript(pk(A) && older(1 week))')
const descriptor = run('wsh(miniscript(pk(A) && older(1 week)))')
const address = run('address(wsh(miniscript(pk(A) && older(1 week))))')
const address2 = run('address(pk(A) && older(1 week))')

console.log({ policy, miniscript, descriptor, address, address2 })
```


## License
MIT
