# libwebauthn

A Linux-native implementation of FIDO2 and FIDO U2F Platform API, fully written in Rust.

This library supports multiple transports (see [Transports](#Transports) for a list) via a pluggable interface, making it easy to add additional backends.

## Credentials for Linux Project

This repository is now part of the [Credentials for Linux][linux-credentials] project, and was previously known as **xdg-credentials-portal**.

The [Credentials for Linux][linux-credentials] project aims to offer FIDO2 platform functionality (FIDO U2F, and WebAuthn) on Linux, over a [D-Bus Portal interface][xdg-portal].

_Looking for the D-Bus API proposal?_ Check out [platform-api][linux-credentials].

## Features

- FIDO U2F
  - 🟢 Registration (U2F_REGISTER)
  - 🟢 Authentication (U2F_AUTHENTICATE)
  - 🟢 Version (U2F_VERSION)
- FIDO2
  - 🟢 Create credential
  - 🟢 Verify assertion
  - 🟢 Biometric user verification
  - 🟢 Discoverable credentials (resident keys)
- FIDO2 to FIDO U2F downgrade
  - 🟢 Basic functionality
  - 🟢 Support for excludeList and pre-flight requests
- PIN/UV Protocols
  - 🟢 PIN/UV Auth Protocol One
  - 🟢 PIN/UV Auth Protocol Two
- PIN/UV Operations
  - 🟢 GetPinToken
  - 🟢 GetPinUvAuthTokenUsingPinWithPermissions
  - 🟢 GetPinUvAuthTokenUsingUvWithPermissions
- [Passkey Authentication][passkeys]
  - 🟢 Discoverable credentials (resident keys)
  - 🟢 Hybrid transport (caBLE v2): QR-initiated transactions
  - 🟠 Hybrid transport (caBLE v2): State-assisted transactions ([#31][#31]: planned)

## Transports

|                      | USB (HID)                 | Bluetooth Low Energy (BLE) | NFC                   | TPM 2.0 (Platform)    | Hybrid (caBLEv2)                   |
| -------------------- | ------------------------- | -------------------------- | --------------------- | --------------------- | ---------------------------------- |
| **FIDO U2F**         | 🟢 Supported (via hidapi) | 🟢 Supported (via bluez)   | 🟠 Planned ([#5][#5]) | 🟠 Planned ([#4][#4]) | N/A                                |
| **WebAuthn (FIDO2)** | 🟢 Supported (via hidapi) | 🟢 Supported (via bluez)   | 🟠 Planned ([#5][#5]) | 🟠 Planned ([#4][#4]) | 🟠 Partly implemented ([#31][#31]) |

## Example programs

After cloning, you can try out [one of the libwebauthn examples](libwebauthn/examples):
```
$ cd libwebauthn
$ git submodule update --init
$ cargo run --example webauthn_hid
$ cargo run --example webauthn_cable
$ cargo run --example u2f_hid
```

## Contributing

We welcome contributions!

If you'd like to contribute but you don't know where to start, check out the _Issues_ tab.

[xdg-portal]: https://flatpak.github.io/xdg-desktop-portal/portal-docs.html
[linux-credentials]: https://github.com/linux-credentials
[webauthn]: https://www.w3.org/TR/webauthn/
[passkeys]: https://fidoalliance.org/passkeys/
[#10]: https://github.com/AlfioEmanueleFresta/xdg-credentials-portal/issues/10
[#3]: https://github.com/AlfioEmanueleFresta/xdg-credentials-portal/issues/3
[#4]: https://github.com/AlfioEmanueleFresta/xdg-credentials-portal/issues/4
[#5]: https://github.com/AlfioEmanueleFresta/xdg-credentials-portal/issues/5
[#17]: https://github.com/AlfioEmanueleFresta/xdg-credentials-portal/issues/17
[#18]: https://github.com/AlfioEmanueleFresta/xdg-credentials-portal/issues/18
[#31]: https://github.com/AlfioEmanueleFresta/xdg-credentials-portal/issues/31
