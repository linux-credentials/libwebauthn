//! Errors specific to the BLE transport.

use crate::transport::ble::btleplug;

#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum BleError {
    #[error("BLE GATT error: {0}")]
    Gatt(#[from] btleplug::Error),
    #[error("BLE framing error: {0}")]
    Framing(#[from] std::io::Error),
    #[error("no supported FIDO revision")]
    NegotiationFailed,
    #[error("device cancelled the operation")]
    Cancelled,
    #[error("unexpected BLE frame")]
    UnexpectedFrame,
}
