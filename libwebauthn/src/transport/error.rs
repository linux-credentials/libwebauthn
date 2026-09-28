//! Per-transport errors live with each transport (e.g. `hid::HidError`,
//! `ble::BleError`, `hybrid::PxpError` from `libwebauthn-pxp`). The ceremony error is
//! [`WebAuthnError`](crate::webauthn::error::WebAuthnError), generic over the
//! channel's concrete transport error.
