use crate::proto::ctap1::apdu::ApduResponseStatus;

// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#error-responses

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CtapError {
    Ok,                     // CTAP1_ERR_SUCCESS, CTAP2_OK
    InvalidCommand,         // CTAP1_ERR_INVALID_COMMAND
    InvalidParameter,       // CTAP1_ERR_INVALID_PARAMETER
    InvalidLength,          // CTAP1_ERR_INVALID_LENGTH
    InvalidSeq,             // CTAP1_ERR_INVALID_SEQ
    Timeout,                // CTAP1_ERR_TIMEOUT
    ChannelBusy,            // CTAP1_ERR_CHANNEL_BUSY
    LockRequired,           // CTAP1_ERR_LOCK_REQUIRED
    InvalidChannel,         // CTAP1_ERR_INVALID_CHANNEL
    InvalidCborType,        // CTAP2_ERR_CBOR_UNEXPECTED_TYPE
    InvalidCbor,            // CTAP2_ERR_INVALID_CBOR
    MissingParameter,       // CTAP2_ERR_MISSING_PARAMETER
    LimitExceeded,          // CTAP2_ERR_LIMIT_EXCEEDED
    UnsupportedExtension,   // CTAP2_ERR_UNSUPPORTED_EXTENSION
    FpDatabaseFull,         // CTAP2_ERR_FP_DATABASE_FULL
    LargeBlobStorageFull,   // CTAP2_ERR_LARGE_BLOB_STORAGE_FULL
    CredentialExcluded,     // CTAP2_ERR_CREDENTIAL_EXCLUDED
    Processing,             // CTAP2_ERR_PROCESSING
    InvalidCredential,      // CTAP2_ERR_INVALID_CREDENTIAL
    UserActionPending,      // CTAP2_ERR_USER_ACTION_PENDING
    OperationPending,       // CTAP2_ERR_OPERATION_PENDING
    NoOperations,           // CTAP2_ERR_NO_OPERATIONS
    UnsupportedAlgorithm,   // CTAP2_ERR_UNSUPPORTED_ALGORITHM
    OperationDenied,        // CTAP2_ERR_OPERATION_DENIED
    KeyStoreFull,           // CTAP2_ERR_KEY_STORE_FULL
    NoOperationPending,     // CTAP2_ERR_NO_OPERATION_PENDING
    UnsupportedOption,      // CTAP2_ERR_UNSUPPORTED_OPTION
    InvalidOption,          // CTAP2_ERR_INVALID_OPTION
    KeepAliveCancel,        // CTAP2_ERR_KEEPALIVE_CANCEL
    NoCredentials,          // CTAP2_ERR_NO_CREDENTIALS
    UserActionTimeout,      // CTAP2_ERR_USER_ACTION_TIMEOUT
    NotAllowed,             // CTAP2_ERR_NOT_ALLOWED
    PINInvalid,             // CTAP2_ERR_PIN_INVALID
    PINBlocked,             // CTAP2_ERR_PIN_BLOCKED
    PINAuthInvalid,         // CTAP2_ERR_PIN_AUTH_INVALID
    PINAuthBlocked,         // CTAP2_ERR_PIN_AUTH_BLOCKED
    PINNotSet,              // CTAP2_ERR_PIN_NOT_SET
    PINRequired,            // CTAP2_ERR_PIN_REQUIRED
    PINPolicyViolation,     // CTAP2_ERR_PIN_POLICY_VIOLATION
    PINTokenExpired,        // CTAP2_ERR_PIN_TOKEN_EXPIRED
    RequestTooLarge,        // CTAP2_ERR_REQUEST_TOO_LARGE
    ActionTimeout,          // CTAP2_ERR_ACTION_TIMEOUT
    UserPresenceRequired,   // CTAP2_ERR_UP_REQUIRED
    UvBlocked,              // CTAP2_ERR_UV_BLOCKED
    IntegrityFailure,       // CTAP2_ERR_INTEGRITY_FAILURE
    InvalidSubcommand,      // CTAP2_ERR_INVALID_SUBCOMMAND
    UVInvalid,              // CTAP2_ERR_UV_INVALID
    UnauthorizedPermission, // CTAP2_ERR_UNAUTHORIZED_PERMISSION
    Other,                  // CTAP1_ERR_OTHER
    // Unmapped, vendor-specific (0xF0-0xFF), and reserved codes are preserved verbatim.
    Unknown(u8),
}

impl CtapError {
    pub fn is_retryable_user_error(&self) -> bool {
        match &self {
            Self::PINInvalid | Self::UVInvalid => true, // PIN or biometric auth failed
            Self::UserActionTimeout => true,            // User action timed out
            _ => false,
        }
    }

    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

impl From<u8> for CtapError {
    fn from(byte: u8) -> Self {
        match byte {
            0x00 => Self::Ok,
            0x01 => Self::InvalidCommand,
            0x02 => Self::InvalidParameter,
            0x03 => Self::InvalidLength,
            0x04 => Self::InvalidSeq,
            0x05 => Self::Timeout,
            0x06 => Self::ChannelBusy,
            0x0A => Self::LockRequired,
            0x0B => Self::InvalidChannel,
            0x11 => Self::InvalidCborType,
            0x12 => Self::InvalidCbor,
            0x14 => Self::MissingParameter,
            0x15 => Self::LimitExceeded,
            0x16 => Self::UnsupportedExtension,
            0x17 => Self::FpDatabaseFull,
            0x18 => Self::LargeBlobStorageFull,
            0x19 => Self::CredentialExcluded,
            0x21 => Self::Processing,
            0x22 => Self::InvalidCredential,
            0x23 => Self::UserActionPending,
            0x24 => Self::OperationPending,
            0x25 => Self::NoOperations,
            0x26 => Self::UnsupportedAlgorithm,
            0x27 => Self::OperationDenied,
            0x28 => Self::KeyStoreFull,
            0x2A => Self::NoOperationPending,
            0x2B => Self::UnsupportedOption,
            0x2C => Self::InvalidOption,
            0x2D => Self::KeepAliveCancel,
            0x2E => Self::NoCredentials,
            0x2F => Self::UserActionTimeout,
            0x30 => Self::NotAllowed,
            0x31 => Self::PINInvalid,
            0x32 => Self::PINBlocked,
            0x33 => Self::PINAuthInvalid,
            0x34 => Self::PINAuthBlocked,
            0x35 => Self::PINNotSet,
            0x36 => Self::PINRequired,
            0x37 => Self::PINPolicyViolation,
            0x38 => Self::PINTokenExpired,
            0x39 => Self::RequestTooLarge,
            0x3A => Self::ActionTimeout,
            0x3B => Self::UserPresenceRequired,
            0x3C => Self::UvBlocked,
            0x3D => Self::IntegrityFailure,
            0x3E => Self::InvalidSubcommand,
            0x3F => Self::UVInvalid,
            0x40 => Self::UnauthorizedPermission,
            0x7F => Self::Other,
            other => Self::Unknown(other),
        }
    }
}

impl From<CtapError> for u8 {
    fn from(error: CtapError) -> Self {
        match error {
            CtapError::Ok => 0x00,
            CtapError::InvalidCommand => 0x01,
            CtapError::InvalidParameter => 0x02,
            CtapError::InvalidLength => 0x03,
            CtapError::InvalidSeq => 0x04,
            CtapError::Timeout => 0x05,
            CtapError::ChannelBusy => 0x06,
            CtapError::LockRequired => 0x0A,
            CtapError::InvalidChannel => 0x0B,
            CtapError::InvalidCborType => 0x11,
            CtapError::InvalidCbor => 0x12,
            CtapError::MissingParameter => 0x14,
            CtapError::LimitExceeded => 0x15,
            CtapError::UnsupportedExtension => 0x16,
            CtapError::FpDatabaseFull => 0x17,
            CtapError::LargeBlobStorageFull => 0x18,
            CtapError::CredentialExcluded => 0x19,
            CtapError::Processing => 0x21,
            CtapError::InvalidCredential => 0x22,
            CtapError::UserActionPending => 0x23,
            CtapError::OperationPending => 0x24,
            CtapError::NoOperations => 0x25,
            CtapError::UnsupportedAlgorithm => 0x26,
            CtapError::OperationDenied => 0x27,
            CtapError::KeyStoreFull => 0x28,
            CtapError::NoOperationPending => 0x2A,
            CtapError::UnsupportedOption => 0x2B,
            CtapError::InvalidOption => 0x2C,
            CtapError::KeepAliveCancel => 0x2D,
            CtapError::NoCredentials => 0x2E,
            CtapError::UserActionTimeout => 0x2F,
            CtapError::NotAllowed => 0x30,
            CtapError::PINInvalid => 0x31,
            CtapError::PINBlocked => 0x32,
            CtapError::PINAuthInvalid => 0x33,
            CtapError::PINAuthBlocked => 0x34,
            CtapError::PINNotSet => 0x35,
            CtapError::PINRequired => 0x36,
            CtapError::PINPolicyViolation => 0x37,
            CtapError::PINTokenExpired => 0x38,
            CtapError::RequestTooLarge => 0x39,
            CtapError::ActionTimeout => 0x3A,
            CtapError::UserPresenceRequired => 0x3B,
            CtapError::UvBlocked => 0x3C,
            CtapError::IntegrityFailure => 0x3D,
            CtapError::InvalidSubcommand => 0x3E,
            CtapError::UVInvalid => 0x3F,
            CtapError::UnauthorizedPermission => 0x40,
            CtapError::Other => 0x7F,
            CtapError::Unknown(byte) => byte,
        }
    }
}

impl std::error::Error for CtapError {}

impl std::fmt::Display for CtapError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Unknown(byte) => write!(f, "Unknown(0x{:02X})", byte),
            _ => write!(
                f,
                "{:?} (retryable user error: {})",
                self,
                self.is_retryable_user_error()
            ),
        }
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

#[cfg(test)]
mod tests {
    use super::CtapError;

    #[test]
    fn all_bytes_round_trip() {
        for byte in 0u8..=0xFF {
            let error = CtapError::from(byte);
            assert_eq!(u8::from(error), byte, "round-trip failed for 0x{byte:02X}");
        }
    }

    #[test]
    fn named_ctap22_codes() {
        assert_eq!(CtapError::from(0x17), CtapError::FpDatabaseFull);
        assert_eq!(CtapError::from(0x18), CtapError::LargeBlobStorageFull);
    }

    #[test]
    fn unknown_codes_preserved() {
        assert_eq!(CtapError::from(0xDE), CtapError::Unknown(0xDE));
        assert_eq!(CtapError::from(0x07), CtapError::Unknown(0x07));
        assert_eq!(CtapError::from(0xF5), CtapError::Unknown(0xF5));
        assert!(!CtapError::from(0xF5).is_known());
        assert!(CtapError::from(0x17).is_known());
    }

    #[test]
    fn unknown_displays_as_hex() {
        assert_eq!(CtapError::Unknown(0xAB).to_string(), "Unknown(0xAB)");
    }
}
