//! Errors specific to the NFC transport.

#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum NfcError {
    #[error("APDU error: {0}")]
    Apdu(#[from] apdu::Error),
    #[cfg(feature = "nfc-backend-pcsc")]
    #[error("PC/SC error: {0}")]
    Pcsc(#[from] pcsc::Error),
    #[cfg(feature = "nfc-backend-libnfc")]
    #[error("libnfc error: {0}")]
    LibNfc(#[from] nfc1::Error),
    #[error("input/output error: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to decode device response: {0}")]
    ResponseDecode(#[source] std::io::Error),
    #[error("response exceeds buffer: {0} bytes")]
    BufferOverflow(usize),
    #[error("no NFC reader available")]
    NoReader,
    #[error("no NFC target selected")]
    NoTarget,
    #[error("no response available")]
    NoResponse,
    #[error("mutex poisoned")]
    MutexPoisoned,
}
