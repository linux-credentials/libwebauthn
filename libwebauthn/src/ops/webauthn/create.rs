use super::idl::Base64UrlString;
use crate::{
    ops::webauthn::{
        MakeCredentialsRequestExtensions, ResidentKeyRequirement, UserVerificationRequirement,
    },
    proto::ctap2::{
        Ctap2CredentialType, Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
        Ctap2PublicKeyCredentialUserEntity,
    },
};

use serde::Deserialize;

/**
 * https://www.w3.org/TR/webauthn-3/#sctn-parseCreationOptionsFromJSON
 */

#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
    #[serde(rename = "residentKey")]
    pub resident_key: Option<ResidentKeyRequirement>,
    #[serde(rename = "requireResidentKey")]
    #[serde(default)]
    pub require_resident_key: bool,
    #[serde(rename = "userVerification")]
    #[serde(default = "default_user_verification")]
    pub user_verification: UserVerificationRequirement,
}

fn default_user_verification() -> UserVerificationRequirement {
    UserVerificationRequirement::Preferred
}

#[derive(Debug, Clone, Deserialize)]
pub struct PublicKeyCredentialCreationOptionsJSON {
    pub rp: Ctap2PublicKeyCredentialRpEntity,
    pub user: Ctap2PublicKeyCredentialUserEntity,
    pub challenge: Base64UrlString,
    #[serde(rename = "pubKeyCredParams")]
    pub params: Vec<Ctap2CredentialType>,
    pub timeout: Option<u32>,
    #[serde(rename = "excludeCredentials")]
    pub exclude_credentials: Vec<Ctap2PublicKeyCredentialDescriptor>,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub hints: Option<Vec<String>>,
    pub attestation: Option<String>,
    #[serde(rename = "attestationFormats")]
    pub attestation_formats: Option<Vec<String>>,
    pub extensions: Option<MakeCredentialsRequestExtensions>,
}
