use super::Base64UrlString;
use crate::{
    ops::webauthn::{
        MakeCredentialsRequestExtensions, ResidentKeyRequirement, UserVerificationRequirement,
    },
    proto::ctap2::{
        Ctap2CredentialType, Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
    },
};

use serde::Deserialize;

/**
 * https://www.w3.org/TR/webauthn-3/#sctn-parseCreationOptionsFromJSON
 */

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorSelectionCriteria {
    pub authenticator_attachment: Option<String>,
    pub resident_key: Option<ResidentKeyRequirement>,
    #[serde(default)]
    pub require_resident_key: bool,
    #[serde(default = "default_user_verification")]
    pub user_verification: UserVerificationRequirement,
}

fn default_user_verification() -> UserVerificationRequirement {
    UserVerificationRequirement::Preferred
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialUserEntity {
    pub id: Base64UrlString,
    pub name: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialCreationOptionsJSON {
    pub rp: Ctap2PublicKeyCredentialRpEntity,
    pub user: PublicKeyCredentialUserEntity,
    pub challenge: Base64UrlString,
    #[serde(rename = "pubKeyCredParams")]
    pub params: Vec<Ctap2CredentialType>,
    pub timeout: Option<u32>,
    pub exclude_credentials: Vec<Ctap2PublicKeyCredentialDescriptor>,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub hints: Option<Vec<String>>,
    pub attestation: Option<String>,
    pub attestation_formats: Option<Vec<String>>,
    pub extensions: Option<MakeCredentialsRequestExtensions>,
}
