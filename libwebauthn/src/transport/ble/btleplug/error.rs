use thiserror;

#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq)]
pub enum Error {
    #[error("invalid framing")]
    InvalidFraming,
    #[error("operation failed")]
    OperationFailed,
    #[error("connection failed")]
    ConnectionFailed,
    #[error("unavailalbe")]
    Unavailable,
    #[error("adapter powered off")]
    PoweredOff,
    #[error("operation canceled")]
    Canceled,
    #[error("operation timed out")]
    Timeout,
}
