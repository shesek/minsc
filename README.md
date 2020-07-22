# Minsc

### A compile-to-Miniscript language for writing Bitcoin scripts

Minsc is a scripting language for writing Bitcoin scripts.
It is based on the [Miniscript](http://bitcoin.sipa.be/miniscript/) Policy language,
with additional features and syntactic sugar sprinkled on top, including variables, functions, infix operators, human-readable times and more.

Documentation and a live compiler are available on the website:
https://shesek.github.io/minsc

Buy me a 🍻 : [bc1q43zm3sdeuehzvpskt2m0gy96pwe7mldxh9d9ta](https://blockstream.info/address/bc1q43zm3sdeuehzvpskt2m0gy96pwe7mldxh9d9ta) or [tippin.me](https://tippin.me/@shesek)

## Examples

```hack
// A user and a 2FA service need to sign off, but after 90 days the user alone is enough

pk(user_pk) && (9@pk(server_pk) || older(90 days))
```
> [:arrow_forward: Try it live](https://shesek.github.io/minsc/#c=%2F%2F%20A%20user%20and%20a%202FA%20service%20need%20to%20sign%20off%2C%20but%20after%2090%20days%20the%20user%20alone%20is%20enough%0A%0Apk(user_pk)%20%26%26%20(9%40pk(server_pk)%20%7C%7C%20older(90%20days)))

```hack
// Traditional preimage-based HTLC

$redeem = pk(A) && sha256(H);
$refund = pk(B) && older(6 blocks);

9@$redeem || $refund
```
> [:arrow_forward: Try it live](https://shesek.github.io/minsc/#c=%2F%2F%20Traditional%20preimage-based%20HTLC%0A%0A%24redeem%20%3D%20pk(A)%20%26%26%20sha256(H)%3B%0A%24refund%20%3D%20pk(B)%20%26%26%20older(6%20blocks)%3B%0A%0A9%40%24redeem%20%7C%7C%20%24refund)

```hack
// Liquid-like federated pegin, with emergency recovery keys

$federation = 4 of [ pk(A), pk(B), pk(C), pk(D), pk(E) ];
$recovery = 2 of [ pk(F), pk(G), pk(H) ];
$delay = heightwise 3 months;

9@$federation || ($recovery && older($delay))
```
> [:arrow_forward: Try it live](https://shesek.github.io/minsc/#c=%2F%2F%20Liquid-like%20federated%20pegin%2C%20with%20emergency%20recovery%20keys%0A%0A%24federation%20%3D%204%20of%20%5B%20pk(A)%2C%20pk(B)%2C%20pk(C)%2C%20pk(D)%2C%20pk(E)%20%5D%3B%0A%24recovery%20%3D%202%20of%20%5B%20pk(F)%2C%20pk(G)%2C%20pk(H)%20%5D%3B%0A%24delay%20%3D%20heightwise%203%20months%3B%0A%0A9%40%24federation%20%7C%7C%20(%24recovery%20%26%26%20older(%24delay)))

```hack
// The BOLT #3 received HTLC policy

fn bolt3_htlc_received($revoke_pk, $local_pk, $remote_pk, $secret, $delay) {
  $success = pk($local_pk) && hash160($secret);
  $timeout = older($delay);

  pk($revoke_pk) || (pk($remote_pk) && ($success || $timeout))
}

bolt3_htlc_received(A, B, C, H, 2 hours)
```
> [:arrow_forward: Try it live](https://shesek.github.io/minsc/#c=%2F%2F%20The%20BOLT%20%233%20received%20HTLC%20policy%0A%0Afn%20bolt3_htlc_received(%24revoke_pk%2C%20%24local_pk%2C%20%24remote_pk%2C%20%24secret%2C%20%24delay)%20%7B%0A%20%20%24success%20%3D%20pk(%24local_pk)%20%26%26%20hash160(%24secret)%3B%0A%20%20%24timeout%20%3D%20older(%24delay)%3B%0A%0A%20%20pk(%24revoke_pk)%20%7C%7C%20(pk(%24remote_pk)%20%26%26%20(%24success%20%7C%7C%20%24timeout))%0A%7D%0A%0Abolt3_htlc_received(A%2C%20B%2C%20C%2C%20H%2C%202%20hours))

[More examples](https://shesek.github.io/minsc) are available on the website.

## Local setup

[Install Rust](https://rustup.rs/) and:

```bash
$ git clone https://github.com/shesek/minsc && cd minsc

# Compile a minsc file
$ cargo run -- examples/htlc.minsc

# Compile from stdin
$ echo 'pk(A) && older(1 week)' | cargo run
```

### License
MIT
