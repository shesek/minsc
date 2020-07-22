# Minsc

### A compile-to-Miniscript language for writing Bitcoin scripts

Minsc is scripting language for writing Bitcoin scripts, implemented in Rust.
It is based on the [Miniscript](http://bitcoin.sipa.be/miniscript/) Policy language,
with additional features and syntactic sugar sprinkled on top, including variables, functions, infix operators, human-readable times and more.

Documentation and a live compiler are available on the website:
https://shesek.github.io/minsc

Buy me a 🍻 : [bc1q43zm3sdeuehzvpskt2m0gy96pwe7mldxh9d9ta](https://blockstream.info/address/bc1q43zm3sdeuehzvpskt2m0gy96pwe7mldxh9d9ta) or [tippin.me](https://tippin.me/@shesek)

### Local setup

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
