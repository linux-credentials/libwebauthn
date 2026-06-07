use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::proto::ctap1::apdu::ApduResponseStatus;

// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#error-responses

#[derive(Debug, IntoPrimitive, TryFromPrimitive, Copy, Clone, PartialEq)]
#[repr(u8)]
pub enum CtapError {
    Ok = 0x00,                     // CTAP1_ERR_SUCCESS, CTAP2_OK
    InvalidCommand = 0x01,         // CTAP1_ERR_INVALID_COMMAND
    InvalidParameter = 0x02,       // CTAP1_ERR_INVALID_PARAMETER
    InvalidLength = 0x03,          // CTAP1_ERR_INVALID_LENGTH
    InvalidSeq = 0x04,             // CTAP1_ERR_INVALID_SEQ
    Timeout = 0x05,                // CTAP1_ERR_TIMEOUT
    ChannelBusy = 0x06,            // CTAP1_ERR_CHANNEL_BUSY
    LockRequired = 0x0A,           // CTAP1_ERR_LOCK_REQUIRED
    InvalidChannel = 0x0B,         // CTAP1_ERR_INVALID_CHANNEL
    InvalidCborType = 0x11,        // CTAP2_ERR_CBOR_UNEXPECTED_TYPE
    InvalidCbor = 0x12,            // CTAP2_ERR_INVALID_CBOR
    MissingParameter = 0x14,       // CTAP2_ERR_MISSING_PARAMETER
    LimitExceeded = 0x15,          // CTAP2_ERR_LIMIT_EXCEEDED,
    UnsupportedExtension = 0x16,   // CTAP2_ERR_UNSUPPORTED_EXTENSION
    CredentialExcluded = 0x19,     // CTAP2_ERR_CREDENTIAL_EXCLUDED
    Processing = 0x21,             // CTAP2_ERR_PROCESSING
    InvalidCredential = 0x22,      // CTAP2_ERR_INVALID_CREDENTIAL
    UserActionPending = 0x23,      // CTAP2_ERR_USER_ACTION_PENDING
    OperationPending = 0x24,       // CTAP2_ERR_OPERATION_PENDING
    NoOperations = 0x25,           // CTAP2_ERR_NO_OPERATIONS
    UnsupportedAlgorithm = 0x26,   // CTAP2_ERR_UNSUPPORTED_ALGORITHM
    OperationDenied = 0x27,        // CTAP2_ERR_OPERATION_DENIED
    KeyStoreFull = 0x28,           // CTAP2_ERR_KEY_STORE_FULL
    NoOperationPending = 0x2A,     // CTAP2_ERR_NO_OPERATION_PENDING
    UnsupportedOption = 0x2B,      // CTAP2_ERR_UNSUPPORTED_OPTION
    InvalidOption = 0x2C,          // CTAP2_ERR_INVALID_OPTION
    KeepAliveCancel = 0x2D,        // CTAP2_ERR_KEEPALIVE_CANCEL
    NoCredentials = 0x2E,          // CTAP2_ERR_NO_CREDENTIALS
    UserActionTimeout = 0x2F,      // CTAP2_ERR_USER_ACTION_TIMEOUT
    NotAllowed = 0x30,             // CTAP2_ERR_NOT_ALLOWED
    PINInvalid = 0x31,             // CTAP2_ERR_PIN_INVALID
    PINBlocked = 0x32,             // CTAP2_ERR_PIN_BLOCKED
    PINAuthInvalid = 0x33,         // CTAP2_ERR_PIN_AUTH_INVALID
    PINAuthBlocked = 0x34,         // CTAP2_ERR_PIN_AUTH_BLOCKED
    PINNotSet = 0x35,              // CTAP2_ERR_PIN_NOT_SET
    PINRequired = 0x36,            // CTAP2_ERR_PIN_REQUIRED
    PINPolicyViolation = 0x37,     // CTAP2_ERR_PIN_POLICY_VIOLATION
    PINTokenExpired = 0x38,        // CTAP2_ERR_PIN_TOKEN_EXPIRED
    RequestTooLarge = 0x39,        // CTAP2_ERR_REQUEST_TOO_LARGE
    ActionTimeout = 0x3A,          // CTAP2_ERR_ACTION_TIMEOUT
    UserPresenceRequired = 0x3B,   // CTAP2_ERR_UP_REQUIRED
    UvBlocked = 0x3C,              // CTAP2_ERR_UV_BLOCKED
    IntegrityFailure = 0x3D,       // CTAP2_ERR_INTEGRITY_FAILURE
    InvalidSubcommand = 0x3E,      // CTAP2_ERR_INVALID_SUBCOMMAND
    UVInvalid = 0x3F,              // CTAP2_ERR_UV_INVALID
    UnauthorizedPermission = 0x40, // CTAP2_ERR_UNAUTHORIZED_PERMISSION
    Other = 0x7F,                  // CTAP1_ERR_OTHER
}

impl CtapError {
    pub fn is_retryable_user_error(&self) -> bool {
        match &self {
            Self::PINInvalid | Self::UVInvalid => true, // PIN or biometric auth failed
            Self::UserActionTimeout => true,            // User action timed out
            _ => false,
        }
    }
}

impl std::error::Error for CtapError {}

impl std::fmt::Display for CtapError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{:?} (retryable user error: {})",
            self,
            self.is_retryable_user_error()
        )
    }
}

impl From<ApduResponseStatus> for CtapError {
    fn from(status: ApduResponseStatus) -> Self {
        match status {
            ApduResponseStatus::NoError => CtapError::Ok,
            ApduResponseStatus::UserPresenceTestFailed => CtapError::UserPresenceRequired,
            ApduResponseStatus::CommandNotAllowed => CtapError::NotAllowed,
            ApduResponseStatus::InvalidKeyHandle => CtapError::NoCredentials,
            ApduResponseStatus::InvalidRequestLength => CtapError::InvalidLength,
            ApduResponseStatus::InvalidClassByte => CtapError::Other,
            ApduResponseStatus::InvalidInstruction => CtapError::InvalidCommand,
        }
    }
}
