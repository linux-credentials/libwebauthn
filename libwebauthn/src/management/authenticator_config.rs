use crate::proto::ctap2::cbor;
use crate::proto::ctap2::Ctap2ClientPinRequest;
use crate::transport::Channel;
pub use crate::webauthn::error::{CtapError, Error, PlatformError};
use crate::webauthn::handle_errors;
use crate::webauthn::pin_uv_auth_token::{user_verification, UsedPinUvAuthToken};
use crate::{
    ops::webauthn::UserVerificationRequirement,
    pin::PinUvAuthProtocol,
    proto::ctap2::{
        Ctap2, Ctap2AuthTokenPermissionRole, Ctap2AuthenticatorConfigCommand,
        Ctap2AuthenticatorConfigRequest, Ctap2GetInfoResponse, Ctap2UserVerifiableRequest,
    },
    UvUpdate,
};
use async_trait::async_trait;
use serde_bytes::ByteBuf;
use std::time::Duration;
use tracing::info;

#[async_trait]
pub trait AuthenticatorConfig {
    async fn toggle_always_uv(&mut self, timeout: Duration) -> Result<(), Error>;

    async fn enable_enterprise_attestation(&mut self, timeout: Duration) -> Result<(), Error>;

    async fn set_min_pin_length(
        &mut self,
        new_pin_length: u64,
        timeout: Duration,
    ) -> Result<(), Error>;

    async fn force_change_pin(&mut self, force: bool, timeout: Duration) -> Result<(), Error>;

    async fn set_min_pin_length_rpids(
        &mut self,
        rpids: Vec<String>,
        timeout: Duration,
    ) -> Result<(), Error>;
}

#[async_trait]
impl<C> AuthenticatorConfig for C
where
    C: Channel,
{
    async fn toggle_always_uv(&mut self, timeout: Duration) -> Result<(), Error> {
        let info = self.ctap2_get_info().await?;
        // CTAP 2.1 6.2.5: toggleAlwaysUv is gated on the alwaysUv option only.
        if !info.option_enabled("authnrCfg") || !info.option_exists("alwaysUv") {
            return Err(Error::Platform(PlatformError::NotSupported));
        }

        let mut req = Ctap2AuthenticatorConfigRequest::new_toggle_always_uv();

        loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Required,
                &mut req,
                timeout,
            )
            .await?;
            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_authenticator_config(&req, timeout).await,
                uv_auth_used,
                timeout
            )
        }
    }

    async fn enable_enterprise_attestation(&mut self, timeout: Duration) -> Result<(), Error> {
        let info = self.ctap2_get_info().await?;
        if !info.option_enabled("authnrCfg") || !info.option_exists("ep") {
            return Err(Error::Platform(PlatformError::NotSupported));
        }

        let mut req = Ctap2AuthenticatorConfigRequest::new_enable_enterprise_attestation();

        loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Required,
                &mut req,
                timeout,
            )
            .await?;
            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_authenticator_config(&req, timeout).await,
                uv_auth_used,
                timeout
            )
        }
    }

    async fn set_min_pin_length(
        &mut self,
        new_pin_length: u64,
        timeout: Duration,
    ) -> Result<(), Error> {
        let info = self.ctap2_get_info().await?;
        if !info.option_enabled("authnrCfg") || !info.option_exists("setMinPINLength") {
            return Err(Error::Platform(PlatformError::NotSupported));
        }

        let mut req = Ctap2AuthenticatorConfigRequest::new_set_min_pin_length(new_pin_length);

        loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Required,
                &mut req,
                timeout,
            )
            .await?;
            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_authenticator_config(&req, timeout).await,
                uv_auth_used,
                timeout
            )
        }
    }

    async fn force_change_pin(&mut self, force: bool, timeout: Duration) -> Result<(), Error> {
        let info = self.ctap2_get_info().await?;
        if !info.option_enabled("authnrCfg") || !info.option_exists("setMinPINLength") {
            return Err(Error::Platform(PlatformError::NotSupported));
        }

        let mut req = Ctap2AuthenticatorConfigRequest::new_force_change_pin(force);

        loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Required,
                &mut req,
                timeout,
            )
            .await?;
            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_authenticator_config(&req, timeout).await,
                uv_auth_used,
                timeout
            )
        }
    }

    async fn set_min_pin_length_rpids(
        &mut self,
        rpids: Vec<String>,
        timeout: Duration,
    ) -> Result<(), Error> {
        let info = self.ctap2_get_info().await?;
        if !info.option_enabled("authnrCfg")
            || !info.option_exists("setMinPINLength")
            || !info.supports_extension("minPinLength")
        {
            return Err(Error::Platform(PlatformError::NotSupported));
        }
        let max_rpids = u64::from(info.max_rpids_for_setminpinlength.unwrap_or(u32::MAX));
        if rpids.len() as u64 > max_rpids {
            return Err(Error::Platform(PlatformError::RequestTooLarge));
        }

        let mut req = Ctap2AuthenticatorConfigRequest::new_set_min_pin_length_rpids(rpids);
        loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Required,
                &mut req,
                timeout,
            )
            .await?;
            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_authenticator_config(&req, timeout).await,
                uv_auth_used,
                timeout
            )
        }
    }
}

impl Ctap2UserVerifiableRequest for Ctap2AuthenticatorConfigRequest {
    fn ensure_uv_set(&mut self) {
        // No-op
    }

    fn calculate_and_set_uv_auth(
        &mut self,
        uv_proto: &dyn PinUvAuthProtocol,
        uv_auth_token: &[u8],
    ) -> Result<(), Error> {
        // pinUvAuthParam (0x04): the result of calling
        // authenticate(pinUvAuthToken, 32×0xff || 0x0d || uint8(subCommand) || subCommandParams).
        let mut data = vec![0xff; 32];
        data.push(0x0D);
        data.push(self.subcommand as u8);
        if self.subcommand == Ctap2AuthenticatorConfigCommand::SetMinPINLength {
            data.extend(cbor::to_vec(&self.subcommand_params)?);
        }
        let uv_auth_param = uv_proto.authenticate(uv_auth_token, &data)?;
        self.protocol = Some(uv_proto.version());
        self.uv_auth_param = Some(ByteBuf::from(uv_auth_param));
        Ok(())
    }

    fn permissions(&self) -> Ctap2AuthTokenPermissionRole {
        Ctap2AuthTokenPermissionRole::AUTHENTICATOR_CONFIGURATION
    }

    fn permissions_rpid(&self) -> Option<&str> {
        None
    }

    fn can_use_uv(&self, info: &Ctap2GetInfoResponse) -> bool {
        info.option_enabled("uvAcfg")
    }

    fn handle_legacy_preview(&mut self, _info: &Ctap2GetInfoResponse) {
        // No-op
    }

    fn needs_shared_secret(&self, _get_info_response: &Ctap2GetInfoResponse) -> bool {
        false
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::time::Duration;

    use super::{AuthenticatorConfig, Error, PlatformError};
    use crate::proto::ctap2::cbor::{self, CborRequest, CborResponse};
    use crate::proto::ctap2::{Ctap2CommandCode, Ctap2GetInfoResponse};
    use crate::transport::mock::channel::MockChannel;

    const TIMEOUT: Duration = Duration::from_secs(1);

    fn push_get_info(channel: &mut MockChannel, info: &Ctap2GetInfoResponse) {
        let req = CborRequest::new(Ctap2CommandCode::AuthenticatorGetInfo);
        let resp = CborResponse::new_success_from_slice(&cbor::to_vec(info).unwrap());
        channel.push_command_pair(req, resp);
    }

    #[tokio::test]
    async fn toggle_always_uv_rejected_when_authnr_cfg_absent() {
        let mut channel = MockChannel::new();
        push_get_info(
            &mut channel,
            &Ctap2GetInfoResponse {
                options: Some(HashMap::from([("alwaysUv".to_string(), false)])),
                ..Default::default()
            },
        );

        let result = channel.toggle_always_uv(TIMEOUT).await;
        assert_eq!(result, Err(Error::Platform(PlatformError::NotSupported)));
    }

    #[tokio::test]
    async fn toggle_always_uv_rejected_when_always_uv_option_absent() {
        let mut channel = MockChannel::new();
        push_get_info(
            &mut channel,
            &Ctap2GetInfoResponse {
                options: Some(HashMap::from([("authnrCfg".to_string(), true)])),
                ..Default::default()
            },
        );

        let result = channel.toggle_always_uv(TIMEOUT).await;
        assert_eq!(result, Err(Error::Platform(PlatformError::NotSupported)));
    }

    #[tokio::test]
    async fn set_min_pin_length_rpids_rejected_when_extension_absent() {
        let mut channel = MockChannel::new();
        push_get_info(
            &mut channel,
            &Ctap2GetInfoResponse {
                options: Some(HashMap::from([
                    ("authnrCfg".to_string(), true),
                    ("setMinPINLength".to_string(), true),
                ])),
                ..Default::default()
            },
        );

        let result = channel
            .set_min_pin_length_rpids(vec!["example.com".to_string()], TIMEOUT)
            .await;
        assert_eq!(result, Err(Error::Platform(PlatformError::NotSupported)));
    }

    #[tokio::test]
    async fn set_min_pin_length_rpids_rejected_when_too_many_rpids() {
        let mut channel = MockChannel::new();
        push_get_info(
            &mut channel,
            &Ctap2GetInfoResponse {
                options: Some(HashMap::from([
                    ("authnrCfg".to_string(), true),
                    ("setMinPINLength".to_string(), true),
                ])),
                extensions: Some(vec!["minPinLength".to_string()]),
                max_rpids_for_setminpinlength: Some(1),
                ..Default::default()
            },
        );

        let rpids = vec!["example.com".to_string(), "example.org".to_string()];
        let result = channel.set_min_pin_length_rpids(rpids, TIMEOUT).await;
        assert_eq!(result, Err(Error::Platform(PlatformError::RequestTooLarge)));
    }
}
