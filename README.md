# Puff

Puff is a fork of v0.2.0 of Lencerf's
[Alioth](https://github.com/google/alioth), further simplified.

The main use case is development/testing of Motor OS; making it
production-ready is not a goal at the moment.

## Building

Install Musl target:

```
rustup target add x86_64-unknown-linux-musl
```

Build:

```
cargo build --release --target=x86_64-unknown-linux-musl
```
