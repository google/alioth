# Error handling in Alioth (WIP)

Error handling in Alioth is done by a combination of the library
[SNAFU](https://crates.io/crates/snafu) , the proc macro `trace_error`, and the
trait `DebugTrace` in [errors.rs](../alioth/src/errors.rs), which is inspired by
GreptimeDB (see references).

Errors are classified into 3 types,

- local errors, for example, division by zero,

- external errors from function calls,

  - non-traceable external errors from the operating system or external
    libraries, which generally do not implement the trait `DebugTrace`,

  - traceable external errors from another Alioth module that implement the
    trait `DebugTrace`.

An example is

```rust
#[trace_error]
#[derive(Snafu, DebugTrace)]
#[snafu(module, context(suffix(false)))]
pub enum Error {
    #[snafu(display("Invalid descriptor id {id}"))]
    InvalidDescriptor { id: u16 }, // local error
    #[snafu(display("Error from OS"))]
    System { error: std::io::Error }, // non-traceable external error
    #[snafu(display("vhost error"))]
    Vhost { source: Box<vhost::Error> }, // traceable external error
    // ...
}
```

As a naming convention, an error variant wraps an external error type with field
name `error` for a non-traceable one (`std::io::Error`) and `source` for a
traceable one (`vhost::Error`).

## Proc macro `trace_error`

The macro `trace_error` augments an error enum by

- adding an extra field `_location: ::snafu::Location` to all enum variants.
  Essentially after macro expansion, the enum `Error` above is extended to

  ```rust
  #[derive(Snafu, DebugTrace)]
  #[snafu(module, context(suffix(false)))]
  pub enum Error {
      #[snafu(display("vhost error"))]
      Vhost {
          #[snafu(source(from(vhost::Error, Box::new)))]
          source: Box<vhost::Error>,
          #[snafu(implicit)]
          _location: ::snafu::Location,
      },
      // ...
  }
  ```

  `_location` is the place in the source code where this error value is
  constructed.

- adding `#[snafu(source)]` to the field `error` or `source` of an external
  error variant,

- adding a `from` conversion if an external error type is wrapped in a `Box` and
  it is not a trait object.

## Trait `DebugTrace` and its derive macro

`#[derive(DebugTrace)]` implements traits `DebugTrace` and `Debug` for an error
enum. Basically, when an error value is `Debug`-printed,

- the method `Debug::fmt()` `Display`-prints itself, which prints the content in
  `#[snafu(display("..."))]` of the error variant,

- if the error value wraps a traceable external error `source`, `Debug::fmt()`
  calls the method `debug_trace()` of `source`,

- if the wrapped `source` further wraps another traceable external error
  `source2`, `debug_trace()` calls the method `debug_trace()` of `source2`,

- continue until a local error or a non-traceable external error is found,

- now `Display`-print the error value and return back to the outer
  `debug_trace()` call, continue until returning back from `Debug::fmt()`.

Putting everything together, when an error value that implements `DebugTrace` is
`Debug`-printed, we get a pseudo-stack-trace like the following,

```text
Error: Failed to create a device
0: No such file or directory (os error 2)
1: Cannot access file "/path/to/disk.img", at alioth/src/virtio/dev/blk.rs:159:14
2: Failed to create a VirtIO device, at alioth/alioth/src/vm.rs:210:19
3: Failed to create a device, at alioth-cli/src/main.rs:266:14
```

## References

1. [Rust 错误处理在 GreptimeDB 的实践](https://mp.weixin.qq.com/s/PK38PtvAETD7pcHeqeDSTA)
   (Rust error handling practice in GreptimeDB). Strongly recommended. Google
   translation should be enough for non-Chinese speakers.

2. [`stack_trace_debug`](https://greptimedb.rs/common_macro/attr.stack_trace_debug.html)
   from GreptimeDB.
