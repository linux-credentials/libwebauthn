use minicbor::{Decode, Encode};

/// Credential protection policy as defined in the CTAP2 spec.
/// 
/// This replaces the ctap_types::ctap2::credential_management::CredentialProtectionPolicy
/// to avoid external dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[cbor(index_only)]
pub enum CredentialProtectionPolicy {
    #[n(1)]
    UserVerificationOptional = 0x01,
    #[n(2)]
    UserVerificationOptionalWithCredentialIdList = 0x02,
    #[n(3)]
    UserVerificationRequired = 0x03,
}

impl Default for CredentialProtectionPolicy {
    fn default() -> Self {
        Self::UserVerificationOptional
    }
}
