[![Build Status](https://travis-ci.org/shesek/minsc.svg?branch=master)](https://travis-ci.org/shesek/minsc)
[![crates.io](https://img.shields.io/crates/v/minsc.svg)](https://crates.io/crates/minsc)
[![npm](https://img.shields.io/npm/v/minsc.svg?color=blue)](https://www.npmjs.com/package/minsc)
[![MIT license](https://img.shields.io/github/license/shesek/minsc.svg?color=yellow)](https://github.com/shesek/minsc/blob/master/LICENSE)
![Pull Requests Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)

# Minsc

### A Miniscript-based scripting language for Bitcoin contracts

Minsc is a high-level scripting language for expressing Bitcoin Script spending conditions.
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
  [:arrow_forward: Try it live](https://min.sc/#c=%2F%2F%20Liquid-like%20federated%20pegin%2C%20with%20emergency%20recovery%20keys%0A%0A%24federation%20%3D%204%20of%20%5B%20pk%28A%29%2C%20pk%28B%29%2C%20pk%28C%29%2C%20pk%28D%29%2C%20pk%28E%29%20%5D%3B%20%0A%24recovery%20%3D%202%20of%20%5B%20pk%28F%29%2C%20pk%28G%29%2C%20pk%28H%29%20%5D%3B%0A%24timeout%20%3D%20older%283%20months%29%3B%0A%0Alikely%40%24federation%20%7C%7C%20%28%24timeout%20%26%26%20%24recovery%29)

- The BOLT #3 received HTLC policy
  ```hack
  fn bolt3_htlc_received($revoke_pk, $local_pk, $remote_pk, $secret, $delay) {
    $success = pk($local_pk) && hash160($secret);
    $timeout = older($delay);

    pk($revoke_pk) || (pk($remote_pk) && ($success || $timeout))
  }

  bolt3_htlc_received(A, B, C, H1, 2 hours)
  ```
  [:arrow_forward: Try it live](https://min.sc/#c=%2F%2F%20The%20BOLT%20%233%20received%20HTLC%20policy%0A%0Afn%20bolt3_htlc_received%28%24revoke_pk%2C%20%24local_pk%2C%20%24remote_pk%2C%20%24secret%2C%20%24delay%29%20%7B%0A%20%20%24success%20%3D%20pk%28%24local_pk%29%20%26%26%20hash160%28%24secret%29%3B%0A%20%20%24timeout%20%3D%20older%28%24delay%29%3B%0A%0A%20%20pk%28%24revoke_pk%29%20%7C%7C%20%28pk%28%24remote_pk%29%20%26%26%20%28%24success%20%7C%7C%20%24timeout%29%29%0A%7D%0A%0Abolt3_htlc_received%28A%2C%20B%2C%20C%2C%20H%2C%202%20hours%29)

- Advanced 2FA where the user has a 2-of-2 setup and the service provider is a 3-of-4 federation
  ```hack
  fn two_factor($user, $provider, $delay) =
    $user && (likely@$provider || older($delay));

  $user = pk(desktop_pk) && pk(mobile_pk);
  $providers = [ pk(A), pk(B), pk(C), pk(D) ];

  two_factor($user, 3 of $providers, 4 months)
  ```
  [:arrow_forward: Try it live](https://min.sc/#c=%2F%2F%20Two%20factor%20authentication%20with%20a%20timeout%20recovery%20clause%0Afn%20two_factor%28%24user%2C%20%24provider%2C%20%24delay%29%20%3D%20%0A%20%20%24user%20%26%26%20%28likely%40%24provider%20%7C%7C%20older%28%24delay%29%29%3B%0A%0A%2F%2F%202FA%20where%20the%20user%20has%20a%202-of-2%20setup%20and%20the%20provider%20is%20a%203-of-4%20federation%0A%0A%24user%20%3D%20pk%28user_desktop%29%20%26%26%20pk%28user_mobile%29%3B%0A%24providers%20%3D%20%5B%20pk%28P1%29%2C%20pk%28P2%29%2C%20pk%28P3%29%2C%20pk%28P4%29%20%5D%3B%0A%0Atwo_factor%28%24user%2C%203%20of%20%24providers%2C%204%20months%29)

More examples are available on https://min.sc.

## Local installation

[Install Rust](https://rustup.rs/) and:

```bash
$ cargo install minsc

# Compile a minsc file
$ minsc examples/htlc.minsc

# Compile from stdin
$ echo 'pk(A) && older(1 week)' | minsc -

# Dump AST
$ minsc examples/htlc.minsc --ast
```

Using the Rust API:
```rust
use minsc::{parse, run};

let code = "pk(A) && older(1 week)";
let ast = parse(code).unwrap();
let result = run(ast).unwrap();

let policy = result.into_policy().unwrap();
println!("{}", policy);

// Also available: into_miniscript() and into_desc()
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
