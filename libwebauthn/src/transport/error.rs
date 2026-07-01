//! Per-transport errors live with each transport (e.g. `hid::HidError`,
//! `ble::BleError`, `cable::CableError`). The ceremony error is
//! [`WebAuthnError`](crate::webauthn::error::WebAuthnError), generic over the
//! channel's concrete transport error.
