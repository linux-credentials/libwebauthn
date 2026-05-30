//! The wire protocol layer for FIDO2/CTAP2 and FIDO U2F/CTAP1 authenticators.
//! This module defines how device commands and responses are encoded and
//! decoded: the CBOR request and response structures for CTAP2, the APDU frames
//! for CTAP1, COSE keys, attestation statements, and the protocol status codes
//! in [`CtapError`]. The [`Ctap1`](ctap1::Ctap1) and [`Ctap2`](ctap2::Ctap2)
//! handlers drive these exchanges at the wire level.
//!
//! Alongside the core commands it covers CTAP2 preflight (checking which
//! credentials a device holds before a ceremony), the PIN/UV authentication
//! protocols, client PIN management, biometric enrollment, and on-device
//! credential management. The encodings follow the FIDO Alliance specifications
//! and account for the difference between APDU-based CTAP1 and CBOR-based CTAP2.

mod error;

pub mod ctap1;
pub mod ctap2;

pub use error::CtapError;
