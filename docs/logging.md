# Logging policy

libwebauthn uses the [`tracing`](https://docs.rs/tracing) crate for all
diagnostics. This document defines how to choose a level, what must never be
logged, and how to write the call. The mechanical rules are enforced by a custom
dylint lint (see [Enforcement](#enforcement)).

## Principles

1. libwebauthn is a library, not an application. Errors reach the caller through
   `Result`. Logging is for diagnosis and must not drive control flow.
2. A run at the default level must be quiet and safe to share. An INFO-level log
   should be safe to paste into a bug report, with no secrets and no per-packet
   noise.
3. Messages are static. Dynamic data goes into structured fields so logs stay
   greppable and machine-parseable.

## Levels

Choose the level by the nature of the event, not by how much you care about it.

### `error!`

Only for faults inside libwebauthn itself: a broken invariant, an unreachable
state, a bug. If correct library code cannot produce the condition, it belongs
at `error!`.

Not for: a device returning a CTAP error status, an IO or transport failure, a
timeout, user cancellation, or an authenticator rejecting a request. Those are
returned to the caller and logged at `warn!` or lower.

### `warn!`

Unexpected behaviour from the device or peer, and recoverable anomalies the
operator may want to know about. For example a malformed or out-of-spec response
that we can still handle, a fallback to a less preferred protocol, an unexpected
field we ignore, or a non-fatal failure we continue past.

### `info!`

Sparse, high-level lifecycle events meaningful to an operator. For example
enumerating devices, establishing a connection, selecting a transport or FIDO
revision, or the start and end of a ceremony. INFO carries no sensitive data and
never appears inside a loop or per packet.

### `debug!`

Developer-facing protocol flow: command and response codes, status, lengths,
small non-sensitive fields, and state transitions. Byte arrays appear here only
as their length. Sensitive values appear here only as a length or a presence
flag, never in full.

### `trace!`

Raw wire data: full byte arrays, raw CBOR and APDU buffers, full request and
response structures, per-packet dumps. This is the only level at which a raw
secret may appear.

## Sensitive data

These are sensitive and must never be logged above `debug!`:

- PINs, PIN hashes, and PIN tokens
- shared secrets and key-agreement material
- `pinUvAuthToken` and `pinUvAuthParam`
- HMAC salts and outputs, and PRF values
- large-blob plaintext
- private keys
- credential IDs
- user handles and user names

At `debug!` log only a length or a presence flag. A full value may appear only
at `trace!`.

## How to write a log call

The message is always a static string literal. Never interpolate (`"{x}"`) and
never pass `format!`. Put dynamic data in fields.

- Use `%value` for `Display` and `?value` for `Debug`.
- Name fields in snake_case: `field = value`.
- One field: bare. Two or more: a brace block.

```rust
// one field: bare
warn!(?err, "Authenticator returned a malformed response");

// two or more fields: brace block
debug!({ rp_id = %rp_id, cred_count = creds.len() }, "Starting preflight");

// byte arrays: length at debug, full bytes at trace
debug!(len = apdu.len(), "Received APDU");
trace!(?apdu, "Received APDU");
```

Prefer a span over repeating the same field on every event. A ceremony or a
transport can open a span carrying shared context such as the transport and the
rp_id.

Do not use `println!`, `eprintln!`, or the `log` crate's macros in the library.
Everything goes through `tracing`.

## Enforcement

A custom dylint lint in [`lints/`](../lints) checks the mechanical rules:

- the message must be a static string literal, with no interpolation or
  `format!`
- no `println!`, `eprintln!`, `print!`, or `eprint!`
- no `log::` macros
- a best-effort denylist flags sensitive field names (pin, secret, token, and so
  on) used at `info!` and above

Level choice, and whether a particular value is sensitive, cannot be decided by a
tool. Those rules are upheld in review against this document.

Run it locally:

```sh
cargo install cargo-dylint dylint-link   # once
cargo dylint --all --workspace -- --all-features
```

CI runs the same command on every push. The three deterministic lints fail the
build. The sensitive-field heuristic stays a warning, since whether a value is
sensitive cannot be decided by a tool.
