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
establishing a connection, selecting a transport or FIDO revision, or the start
and end of a ceremony. INFO carries no sensitive values and no per-device
identifiers, and never appears inside a loop or per packet. Device enumeration
is polled by callers, so it logs the count at `debug!` and the device list at
`trace!`.

### `debug!`

Developer-facing protocol flow: command and response codes, status, lengths,
small non-sensitive fields, and state transitions. Byte arrays appear here only
as their length, except per-device identifiers (see
[Device identifiers](#device-identifiers)). Sensitive values appear here only
as a length or a presence flag, never in full.

### `trace!`

Raw wire data: full byte arrays, raw CBOR and APDU buffers, full request and
response structures, per-packet dumps. This is the only level at which a raw
secret may appear.

## Sensitive data

These are sensitive:

- PINs, PIN hashes, and PIN tokens
- shared secrets and key-agreement material
- `pinUvAuthToken` and `pinUvAuthParam`
- HMAC salts and outputs, and PRF values
- large-blob plaintext
- private keys
- credential IDs
- user handles and user names
- hybrid linking secrets: the QR secret, the link secret, and keys derived
  from them

A sensitive value may appear in full only at `trace!`. At every other level,
log only its length or a presence flag. A length or a presence flag is not the
value, so it can go at whatever level the event calls for. For example, an HMAC
output of the wrong length from the device is a `warn!` that carries the length.

The exception is a length that narrows down a secret the user chose, such as
the length of a PIN. Keep that at `debug!` or below.

## Device identifiers

Connection details change on replug or per session and identify nothing on
their own: hidraw paths, USB bus and address, the HID channel ID, the L2CAP
PSM, and the hybrid routing and tunnel IDs. Model details are shared by every
unit of a model: USB vendor and product IDs, manufacturer and product strings,
firmware versions, and the AAGUID. Both may be logged at any level.

Per-device identifiers can follow one device, and so its user, across logs.
Unlike sensitive data, they may appear in full at `debug!`. Never log them at
`info!` or above:

- Bluetooth addresses, including btleplug peripheral IDs and BlueZ object
  paths, which embed the address
- USB serial numbers, including PC/SC reader names, since pcscd appends the
  serial number by default
- NFC card UIDs
- Bluetooth local names and hybrid authenticator names, which may be
  user-chosen
- hybrid known-device IDs, contact IDs, and link IDs
- the device identifier recovered from `encIdentifier`

This covers span fields too. An `#[instrument]` span is `info` unless it sets a
level, so one that carries a per-device identifier sets `level = Level::DEBUG`.

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

```rust
// shared context: once on the span, not on every event
#[instrument(level = Level::DEBUG, skip_all, fields(cmd = ?msg.cmd, payload_len = msg.payload.len()))]
async fn hid_send(&self, msg: &HidMessage) -> Result<(), HidError> {
    for (i, packet) in packets.iter().enumerate() {
        // cmd and payload_len come from the span
        debug!({ packet = i, len = packet.len() }, "Sending packet as HID report");
    }
}
```

Span fields follow the same rules as event fields. A span's fields are printed
with every event inside it whenever the span's level is enabled. By default
`#[instrument]` opens the span at `info`, records every argument with `Debug`,
and logs an `err` return at `error`. So:

- Always set `level` explicitly, chosen as for an event. Per-message and
  polled spans use `Level::DEBUG`.
- Pass `skip_all` by default and opt values in with `fields(...)`.
- Give `err` an explicit level, since most errors are returned to the caller
  and belong at `warn!` or lower (see [`error!`](#error)).
- Never use `ret` on a function that returns a secret.

Do not use `println!`, `eprintln!`, or the `log` crate's macros in the library.
Everything goes through `tracing`.

## Enforcement

A custom dylint lint in [`lints/`](../lints) checks the mechanical rules:

- the message must be a static string literal, with no interpolation or
  `format!`
- no `println!`, `eprintln!`, `print!`, or `eprint!`
- no `log::` macros
- a best-effort denylist flags sensitive field names (pin, secret, token, and so
  on) used at `info!` and above, except length and count fields such as
  `token_len`

Level choice, whether a particular value is sensitive or identifies a device,
and the PIN length exception cannot be decided by a tool. Those rules are
upheld in review against this document. The lint does not inspect
`#[instrument]` attributes, so the span rules are upheld in review too.

Run it locally:

```sh
cargo install cargo-dylint dylint-link   # once
cargo dylint --all --workspace -- --all-features
```

CI runs the same command on every push. The three deterministic lints fail the
build. The sensitive-field heuristic stays a warning, since whether a value is
sensitive cannot be decided by a tool.
