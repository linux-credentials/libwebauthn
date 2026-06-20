//! Errors specific to the USB HID transport.

#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum HidError {
    #[error("failed to initialize hidapi: {0}")]
    ApiInit(#[source] hidapi::HidError),
    #[error("failed to open HID device: {0}")]
    Open(#[source] hidapi::HidError),
    #[error("failed to write to HID device: {0}")]
    Write(#[source] hidapi::HidError),
    #[error("failed to read from HID device: {0}")]
    Read(#[source] hidapi::HidError),
    #[error("failed to parse INIT response: {0}")]
    InitResponseParse(#[source] std::io::Error),
    #[error("failed to encode HID packets: {0}")]
    PacketEncode(#[source] std::io::Error),
    #[error("failed to parse HID frame: {0}")]
    FrameParse(#[source] std::io::Error),
    #[error("failed to decode device response: {0}")]
    ResponseDecode(#[source] std::io::Error),
    #[error("HID read task failed: {0}")]
    TaskJoin(#[source] tokio::task::JoinError),
    #[error("invalid INIT response")]
    InvalidInit,
    #[error("HID device lock poisoned")]
    DeviceLockPoisoned,
    #[error("HID operation timed out")]
    Timeout,
    #[error("HID operation cancelled")]
    Cancelled,
}
