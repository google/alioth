# WASM VMM

WASM VMM is a fork of v0.2.0 of Lencerf's
[Alioth](https://github.com/google/alioth), further simplified.

## Building

Install Musl target:

```
rustup target add x86_64-unknown-linux-musl
```

Build:

```
cargo build --release --target=x86_64-unknown-linux-musl
```
