# logging_lints

Custom [dylint](https://github.com/trailofbits/dylint) lints that enforce the
mechanical parts of the libwebauthn [logging policy](../../docs/logging.md).

They run before macro expansion, so they inspect the macro tokens as written.

## Lints

- **`tracing_message_interpolation`** — a `tracing` event or span message must be
  a static string literal. Flags interpolated messages (`info!("got {x}")`,
  `info!("got {}", x)`) and messages built with `format!`. Dynamic data belongs
  in structured fields.
- **`print_macro_in_library`** — flags `print!`, `println!`, `eprint!`,
  `eprintln!`. Library code logs through `tracing`.
- **`log_crate_macro`** — flags `log::` macros. libwebauthn standardises on
  `tracing`.
- **`sensitive_field_above_debug`** — best-effort denylist that flags
  sensitive-looking field names (pin, secret, token, shared secret, credential
  id, ...) used at `info!` and above. Length and presence fields (`*_len`,
  `*_count`) and PIN protocol metadata (`pin_protocol`) are not flagged. This is
  a heuristic and can have false positives. Silence a checked case with
  `#[allow(dylint::sensitive_field_above_debug)]`.

## Running

```sh
cargo install cargo-dylint dylint-link   # once
cargo dylint --all --workspace -- --all-features
```

The lints are registered for the workspace in the top-level `Cargo.toml` under
`[workspace.metadata.dylint]`, and run in CI (`.github/workflows/dylint.yml`),
where the three deterministic lints fail the build.

## Toolchain

This crate builds on the pinned nightly in `rust-toolchain` with `rustc_private`.
It is deliberately kept out of the main workspace so the library still builds on
stable. Bump it with `cargo dylint upgrade logging_lints` when updating dylint.
