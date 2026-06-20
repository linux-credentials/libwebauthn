use super::get::PublicKeyCredentialDescriptorJSON;
use super::Base64UrlString;
use crate::{
    ops::webauthn::{
        MakeCredentialsRequestExtensions, ResidentKeyRequirement, UserVerificationRequirement,
    },
    proto::ctap2::Ctap2CredentialType,
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

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialRpEntityJSON {
    pub id: Option<String>,
    pub name: Option<String>,
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
    pub rp: PublicKeyCredentialRpEntityJSON,
    pub user: PublicKeyCredentialUserEntity,
    pub challenge: Base64UrlString,
    #[serde(rename = "pubKeyCredParams")]
    pub params: Vec<Ctap2CredentialType>,
    pub timeout: Option<u32>,
    #[serde(default)]
    pub exclude_credentials: Vec<PublicKeyCredentialDescriptorJSON>,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub hints: Option<Vec<String>>,
    pub attestation: Option<String>,
    pub attestation_formats: Option<Vec<String>>,
    pub extensions: Option<MakeCredentialsRequestExtensions>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::ctap2::Ctap2PublicKeyCredentialDescriptor;

    #[test]
    fn exclude_credentials_id_is_base64url_decoded() {
        let json = r#"{
            "rp": { "id": "example.org", "name": "Example" },
            "user": { "id": "YWxpY2U", "name": "alice", "displayName": "Alice" },
            "challenge": "Y2hhbGxlbmdl",
            "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
            "excludeCredentials": [{ "type": "public-key", "id": "AQIDBA" }]
        }"#;
        let options: PublicKeyCredentialCreationOptionsJSON = serde_json::from_str(json).unwrap();
        let descriptor: Ctap2PublicKeyCredentialDescriptor =
            options.exclude_credentials[0].clone().into();
        assert_eq!(descriptor.id, [1u8, 2, 3, 4]);
    }

    #[test]
    fn exclude_credentials_defaults_to_empty_when_omitted() {
        let json = r#"{
            "rp": { "id": "example.org", "name": "Example" },
            "user": { "id": "YWxpY2U", "name": "alice", "displayName": "Alice" },
            "challenge": "Y2hhbGxlbmdl",
            "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }]
        }"#;
        let options: PublicKeyCredentialCreationOptionsJSON = serde_json::from_str(json).unwrap();
        assert!(options.exclude_credentials.is_empty());
    }
}
