#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Error {
    InvalidFraming,
    OperationFailed,
    ConnectionFailed,
    Unavailable,
    PoweredOff,
    Canceled,
    Timeout,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
