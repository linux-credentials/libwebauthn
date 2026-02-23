mod client_data;
mod get_assertion;
pub mod idl;
mod make_credential;
mod timeout;
pub mod related_origins;

use super::u2f::{RegisterRequest, SignRequest};
use crate::webauthn::CtapError;
pub use client_data::ClientData;
pub use get_assertion::{
    Assertion, Ctap2HMACGetSecretOutput, GetAssertionHmacOrPrfInput,
    GetAssertionLargeBlobExtension, GetAssertionLargeBlobExtensionOutput, GetAssertionPrfOutput,
    GetAssertionRequest, GetAssertionRequestExtensions, GetAssertionResponse,
    GetAssertionResponseExtensions, GetAssertionResponseUnsignedExtensions, HMACGetSecretInput,
    HMACGetSecretOutput, PRFValue, PrfInput,
};
pub use idl::{
    rpid::RelyingPartyId, AuthenticationExtensionsClientOutputsJSON, AuthenticationResponseJSON,
    AuthenticatorAssertionResponseJSON, AuthenticatorAttestationResponseJSON, Base64UrlString,
    JsonFormat, RegistrationResponseJSON, ResponseSerializationError, WebAuthnIDL,
    WebAuthnIDLResponse,
};
pub use make_credential::{
    CredentialPropsExtension, CredentialProtectionExtension, CredentialProtectionPolicy,
    MakeCredentialLargeBlobExtension, MakeCredentialLargeBlobExtensionOutput,
    MakeCredentialPrfInput, MakeCredentialPrfOutput, MakeCredentialRequest, MakeCredentialResponse,
    MakeCredentialsRequestExtensions, MakeCredentialsResponseExtensions,
    MakeCredentialsResponseUnsignedExtensions, ResidentKeyRequirement,
};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq)]
pub enum Operation {
    MakeCredential,
    GetAssertion,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UserVerificationRequirement {
    Required,
    Discouraged,
    #[default]
    #[serde(other)]
    Preferred,
}

impl UserVerificationRequirement {
    /// Check if user verification is discouraged
    pub fn is_discouraged(&self) -> bool {
        match self {
            Self::Required | Self::Preferred => false,
            Self::Discouraged => true,
        }
    }

    /// Check if user verification is preferred or required for this request
    pub fn is_preferred(&self) -> bool {
        match self {
            Self::Required | Self::Preferred => true,
            Self::Discouraged => false,
        }
    }

    /// Check if user verification is strictly required for this request
    pub fn is_required(&self) -> bool {
        match self {
            Self::Required => true,
            Self::Preferred | Self::Discouraged => false,
        }
    }
}

pub trait DowngradableRequest<T> {
    fn is_downgradable(&self) -> bool;
    fn try_downgrade(&self) -> Result<T, CtapError>;
}

#[cfg(test)]
mod tests {
    use crate::ops::webauthn::make_credential::ResidentKeyRequirement;
    use crate::ops::webauthn::{
        DowngradableRequest, MakeCredentialRequest, UserVerificationRequirement,
    };
    use crate::proto::ctap2::{
        Ctap2COSEAlgorithmIdentifier, Ctap2CredentialType, Ctap2PublicKeyCredentialType,
    };

    #[test]
    fn ctap2_make_credential_downgradable() {
        let mut request = MakeCredentialRequest::dummy();
        request.algorithms = vec![Ctap2CredentialType::default()];
        request.resident_key = Some(ResidentKeyRequirement::Discouraged);
        assert!(request.is_downgradable());
    }

    #[test]
    fn ctap2_make_credential_downgradable_unsupported_rk() {
        let mut request = MakeCredentialRequest::dummy();
        request.algorithms = vec![Ctap2CredentialType::default()];
        request.resident_key = Some(ResidentKeyRequirement::Required);
        assert!(!request.is_downgradable());
    }

    #[test]
    fn ctap2_make_credential_downgradable_unsupported_uv() {
        let mut request = MakeCredentialRequest::dummy();
        request.algorithms = vec![Ctap2CredentialType::default()];
        request.user_verification = UserVerificationRequirement::Required;
        assert!(!request.is_downgradable());
    }

    #[test]
    fn ctap2_make_credential_downgradable_unsupported_algorithm() {
        let mut request = MakeCredentialRequest::dummy();
        request.algorithms = vec![Ctap2CredentialType::new(
            Ctap2PublicKeyCredentialType::PublicKey,
            Ctap2COSEAlgorithmIdentifier::EDDSA,
        )];
        assert!(!request.is_downgradable());
    }
}
