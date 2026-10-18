//! Client platform side of the FIDO Proximity Exchange Protocol (PXP),
//! formerly the CTAP hybrid transport (caBLE).
//!
//! PXP covers invocation (QR code or state-assisted), proximity proof over a
//! BLE advertisement, channel negotiation (WebSocket tunnel or BLE L2CAP), the
//! Noise handshake, and the encrypted message exchange. CTAP messages are
//! carried as opaque frames. The only CTAP this crate knows is what PXP itself
//! requires: the getInfo command byte and the getInfo response structure.
//! `libwebauthn` builds its hybrid transport on top.
//!
//! See <https://fidoalliance.org/specs/hybrid/>.

// Production code must not panic. Tests keep unwrap/expect/panic latitude
// through `not(test)`.
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(not(test), deny(clippy::expect_used))]
#![cfg_attr(not(test), deny(clippy::panic))]
#![cfg_attr(not(test), deny(clippy::todo))]
#![cfg_attr(not(test), deny(clippy::unreachable))]
#![cfg_attr(not(test), deny(clippy::indexing_slicing))]
#![cfg_attr(not(test), deny(clippy::unwrap_in_result))]

mod ble;
mod cbor;
mod connection_stages;
mod crypto;
mod data_channel;
mod digit_encode;
mod get_info;
mod l2cap;
mod protocol;

pub mod advertisement;
pub mod connection;
pub mod error;
pub mod known_devices;
pub mod qr_code_device;
pub mod tunnel;

pub use connection::{
    connect, ConnectTarget, ConnectionState, PxpUpdate, TunnelHandle, UpdateSink,
};
pub use digit_encode::digit_encode;
