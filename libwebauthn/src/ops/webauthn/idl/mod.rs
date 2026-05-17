mod base64url;
pub mod create;
pub mod get;
pub mod origin;
pub mod response;
pub mod rpid;

pub use base64url::Base64UrlString;
pub use response::{
    AuthenticationExtensionsClientOutputsJSON, AuthenticationResponseJSON,
    AuthenticatorAssertionResponseJSON, AuthenticatorAttestationResponseJSON,
    CredentialPropertiesOutputJSON, HMACGetSecretOutputJSON, JsonFormat, LargeBlobOutputJSON,
    PRFOutputJSON, PRFValuesJSON, RegistrationResponseJSON, ResponseSerializationError,
    WebAuthnIDLResponse,
};

use async_trait::async_trait;
use origin::RequestOrigin;
use serde::de::DeserializeOwned;
use serde_json;

use super::psl::PublicSuffixList;
use super::related_origins::RelatedOriginsHttpClient;

pub type JsonError = serde_json::Error;

#[async_trait]
pub trait WebAuthnIDL<E>: Sized
where
    E: std::error::Error,
    Self: FromIdlModel<Self::IdlModel, E>,
{
    type Error: std::error::Error + From<JsonError> + From<E>;
    type IdlModel: DeserializeOwned + Send;

    async fn from_json(
        request_origin: &RequestOrigin,
        psl: &dyn PublicSuffixList,
        http: &dyn RelatedOriginsHttpClient,
        json: &str,
    ) -> Result<Self, Self::Error> {
        let idl_model: Self::IdlModel = serde_json::from_str(json)?;
        Self::from_idl_model(request_origin, psl, http, idl_model)
            .await
            .map_err(From::from)
    }
}

#[async_trait]
pub trait FromIdlModel<T, E>: Sized
where
    T: DeserializeOwned + Send,
    E: std::error::Error,
{
    async fn from_idl_model(
        request_origin: &RequestOrigin,
        psl: &dyn PublicSuffixList,
        http: &dyn RelatedOriginsHttpClient,
        model: T,
    ) -> Result<Self, E>;
}
