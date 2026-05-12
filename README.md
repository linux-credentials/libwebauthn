# libwebauthn

A Linux-native implementation of FIDO2 and FIDO U2F Platform API, fully written in Rust.

This library supports multiple transports (see [Transports](#Transports) for a list) via a pluggable interface, making it easy to add additional backends.

## Credentials for Linux Project

This repository is now part of the [Credentials for Linux][linux-credentials] project, and was previously known as **xdg-credentials-portal**.

The [Credentials for Linux][linux-credentials] project aims to offer FIDO2 platform functionality (FIDO U2F, and WebAuthn) on Linux, over a [D-Bus Portal interface][xdg-portal].

_Looking for the D-Bus API proposal?_ Check out [credentialsd][credentialsd].

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
  - 🟢 Hybrid transport (caBLE v2): State-assisted transactions (remember this phone)

## Runtime requirements

Validating the relying party ID against the calling origin requires the [Public Suffix List][psl]. The built-in loader reads it from the standard system path. The `publicsuffix` package on Debian/Ubuntu or `publicsuffix-list` on Fedora and Arch installs it there, but these are not always present on minimal installs. Install explicitly if needed. Callers wiring their own list don't need a system package.

## Transports

|                              | FIDO U2F              | WebAuthn (FIDO2)      |
| ---------------------------- | --------------------- | --------------------- |
| **USB (HID)**                | 🟢 Supported (hidapi) | 🟢 Supported (hidapi) |
| **Bluetooth Low Energy**     | 🟢 Supported (bluez)  | 🟢 Supported (bluez)  |
| **NFC**                      | 🟢 Supported (pcsc or libnfc) | 🟢 Supported (pcsc or libnfc) |
| **TPM 2.0 (Platform)**       | 🟠 Planned ([#4][#4]) | 🟠 Planned ([#4][#4]) |
| **Hybrid (QR code scan, aka caBLE v2)**         | N/A                   | 🟢 Supported          |

## Example programs

After cloning, you can try out [one of the libwebauthn examples](libwebauthn/examples):

```
$ cd libwebauthn
$ git submodule update --init
```

| Transport             | FIDO U2F                                                                                                                       | WebAuthn (FIDO2)                                                                                                                           |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| **USB (HID)**         | `cargo run --example u2f_hid`                                                                                                  | `cargo run --example webauthn_hid`<br>`cargo run --example webauthn_json_hid`                                                              |
| **Bluetooth (BLE)**   | `cargo run --example u2f_ble`                                                                                                  | —                                                                                                                                          |
| **NFC** [^nfc]        | `cargo run --features nfc-backend-pcsc --example u2f_nfc`<br>`cargo run --features nfc-backend-libnfc --example u2f_nfc`       | `cargo run --features nfc-backend-pcsc --example webauthn_nfc`<br>`cargo run --features nfc-backend-libnfc --example webauthn_nfc`         |
| **Hybrid (caBLE v2)** | —                                                                                                                              | `cargo run --example webauthn_cable`                                                                                                       |

[^nfc]: `nfc-backend-pcsc` is pure userspace and recommended on most systems. `nfc-backend-libnfc` requires the `libnfc` system library. Both can be enabled together; the first FIDO device found by either backend is used.

Additional HID-only examples cover specific FIDO2 features and authenticator management:

```
$ cargo run --example webauthn_extensions_hid
$ cargo run --example webauthn_preflight_hid
$ cargo run --example webauthn_prf_hid
$ cargo run --example prf_test
$ cargo run --example hid_device_selection
$ cargo run --example change_pin_hid
$ cargo run --example bio_enrollment_hid
$ cargo run --example authenticator_config_hid
$ cargo run --example cred_management
```

## Contributing

We welcome contributions!

Join the discussion on Matrix at `#credentials-for-linux:matrix.org`.

If you don't know where to start, check out the _Issues_ tab.

[xdg-portal]: https://flatpak.github.io/xdg-desktop-portal/portal-docs.html
[linux-credentials]: https://github.com/linux-credentials
[credentialsd]: https://github.com/linux-credentials/credentialsd
[webauthn]: https://www.w3.org/TR/webauthn/
[passkeys]: https://fidoalliance.org/passkeys/
[#10]: https://github.com/linux-credentials/libwebauthn/issues/10
[#3]: https://github.com/linux-credentials/libwebauthn/issues/3
[#4]: https://github.com/linux-credentials/libwebauthn/issues/4
[#17]: https://github.com/linux-credentials/libwebauthn/issues/17
[#18]: https://github.com/linux-credentials/libwebauthn/issues/18
[#31]: https://github.com/linux-credentials/libwebauthn/issues/31
[psl]: https://publicsuffix.org/
