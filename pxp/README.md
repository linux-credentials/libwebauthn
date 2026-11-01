# pxp

A Linux-native implementation of the [FIDO2 Proximity Exchange Protocol (PXP) spec][pxp-spec], fully written in Rust.

PXP, formerly the FIDO2 hybrid transport, allows a FIDO2 client and authenticator to communicate over a Bluetooth or Websocket tunnel after initiation via via QR code scan or NFC and establishing physical proximity over BLE.

## Features

- Initiation
  - 🟢 QR code
  - 🟢 State-assisted
  - 🟠 NFC
- Data channel
  - 🟢 BLE
  - 🟢 Websockets

## Minimum Supported Rust Version (MSRV)

`pxp` uses Rust edition 2021 and tracks recent stable Rust. CI builds and tests on the current stable toolchain. There is no separate older MSRV floor: if a recent stable `rustc` builds the crate, it is supported.

## License

Licensed under the GNU Lesser General Public License v2.1 or later (`LGPL-2.1-or-later`). See [COPYING](COPYING) for the full text.

## Contributing

We welcome contributions!

Join the discussion on Matrix at `#credentials-for-linux:matrix.org`.

If you don't know where to start, check out the _Issues_ tab.

[pxp-spec]: https://fidoalliance.org/specs/hybrid/proximity-exchange-protocol-v1.0-wd-20260717.html
