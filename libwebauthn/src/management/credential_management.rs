use crate::proto::ctap2::cbor;
use crate::{
    ops::webauthn::UserVerificationRequirement,
    pin::PinUvAuthProtocol,
    proto::ctap2::{
        Ctap2, Ctap2AuthTokenPermissionRole, Ctap2ClientPinRequest, Ctap2CredentialData,
        Ctap2CredentialManagementMetadata, Ctap2CredentialManagementRequest, Ctap2GetInfoResponse,
        Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialUserEntity, Ctap2RPData,
        Ctap2UserVerifiableRequest,
    },
    transport::Channel,
    unwrap_field,
    webauthn::{
        error::{CtapError, PlatformError, WebAuthnError},
        handle_errors,
        pin_uv_auth_token::{user_verification, UsedPinUvAuthToken},
    },
    UvUpdate,
};
use async_trait::async_trait;
use serde_bytes::ByteBuf;
use std::time::Duration;
use tracing::info;

#[async_trait]
pub trait CredentialManagement: Channel {
    async fn get_credential_metadata(
        &mut self,
        timeout: Duration,
    ) -> Result<Ctap2CredentialManagementMetadata, WebAuthnError<Self::TransportError>>;
    async fn enumerate_rps_begin(
        &mut self,
        timeout: Duration,
    ) -> Result<(Ctap2RPData, u64), WebAuthnError<Self::TransportError>>;
    async fn enumerate_rps_next_rp(
        &mut self,
        timeout: Duration,
    ) -> Result<Ctap2RPData, WebAuthnError<Self::TransportError>>;
    async fn enumerate_credentials_begin(
        &mut self,
        rpid_hash: &[u8],
        timeout: Duration,
    ) -> Result<(Ctap2CredentialData, u64), WebAuthnError<Self::TransportError>>;
    async fn enumerate_credentials_next(
        &mut self,
        timeout: Duration,
    ) -> Result<Ctap2CredentialData, WebAuthnError<Self::TransportError>>;
    async fn delete_credential(
        &mut self,
        credential_id: &Ctap2PublicKeyCredentialDescriptor,
        timeout: Duration,
    ) -> Result<(), WebAuthnError<Self::TransportError>>;
    async fn update_user_info(
        &mut self,
        credential_id: &Ctap2PublicKeyCredentialDescriptor,
        user: &Ctap2PublicKeyCredentialUserEntity,
        timeout: Duration,
    ) -> Result<(), WebAuthnError<Self::TransportError>>;
}

#[async_trait]
impl<C> CredentialManagement for C
where
    C: Channel,
{
    async fn get_credential_metadata(
        &mut self,
        timeout: Duration,
    ) -> Result<Ctap2CredentialManagementMetadata, WebAuthnError<Self::TransportError>> {
        let mut req = Ctap2CredentialManagementRequest::new_get_credential_metadata();
        let resp = loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Preferred,
                &mut req,
                timeout,
            )
            .await?;

            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_credential_management(&req, timeout).await,
                uv_auth_used,
                timeout,
                req
            )
        }?;
        let metadata = Ctap2CredentialManagementMetadata::new(
            unwrap_field!(resp.existing_resident_credentials_count),
            unwrap_field!(resp.max_possible_remaining_resident_credentials_count),
        );
        Ok(metadata)
    }

    async fn enumerate_rps_begin(
        &mut self,
        timeout: Duration,
    ) -> Result<(Ctap2RPData, u64), WebAuthnError<Self::TransportError>> {
        let mut req = Ctap2CredentialManagementRequest::new_enumerate_rps_begin();
        let resp = loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Preferred,
                &mut req,
                timeout,
            )
            .await?;

            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_credential_management(&req, timeout).await,
                uv_auth_used,
                timeout,
                req
            )
        }?;
        self.set_cred_mgmt_preview(req.use_legacy_preview);
        Ok((
            Ctap2RPData::new(
                unwrap_field!(resp.rp),
                unwrap_field!(resp.rp_id_hash).into_vec(),
            ),
            unwrap_field!(resp.total_rps),
        ))
    }

    async fn enumerate_rps_next_rp(
        &mut self,
        timeout: Duration,
    ) -> Result<Ctap2RPData, WebAuthnError<Self::TransportError>> {
        let mut req = Ctap2CredentialManagementRequest::new_enumerate_rps_next_rp();
        req.use_legacy_preview = self.cred_mgmt_preview();
        let resp = self.ctap2_credential_management(&req, timeout).await?;
        Ok(Ctap2RPData::new(
            unwrap_field!(resp.rp),
            unwrap_field!(resp.rp_id_hash).into_vec(),
        ))
    }

    async fn enumerate_credentials_begin(
        &mut self,
        rpid_hash: &[u8],
        timeout: Duration,
    ) -> Result<(Ctap2CredentialData, u64), WebAuthnError<Self::TransportError>> {
        let mut req = Ctap2CredentialManagementRequest::new_enumerate_credentials_begin(rpid_hash);
        let resp = loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Preferred,
                &mut req,
                timeout,
            )
            .await?;

            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_credential_management(&req, timeout).await,
                uv_auth_used,
                timeout,
                req
            )
        }?;
        self.set_cred_mgmt_preview(req.use_legacy_preview);
        let cred = Ctap2CredentialData::new(
            unwrap_field!(resp.user),
            unwrap_field!(resp.credential_id),
            unwrap_field!(resp.public_key).into_bytes(),
            unwrap_field!(resp.cred_protect),
            resp.large_blob_key.map(|x| x.into_vec()),
        );
        let total_creds = unwrap_field!(resp.total_credentials);
        Ok((cred, total_creds))
    }

    async fn enumerate_credentials_next(
        &mut self,
        timeout: Duration,
    ) -> Result<Ctap2CredentialData, WebAuthnError<Self::TransportError>> {
        let mut req = Ctap2CredentialManagementRequest::new_enumerate_credentials_next();
        req.use_legacy_preview = self.cred_mgmt_preview();
        let resp = self.ctap2_credential_management(&req, timeout).await?;
        let cred = Ctap2CredentialData::new(
            unwrap_field!(resp.user),
            unwrap_field!(resp.credential_id),
            unwrap_field!(resp.public_key).into_bytes(),
            unwrap_field!(resp.cred_protect),
            resp.large_blob_key.map(|x| x.into_vec()),
        );
        Ok(cred)
    }

    async fn delete_credential(
        &mut self,
        credential_id: &Ctap2PublicKeyCredentialDescriptor,
        timeout: Duration,
    ) -> Result<(), WebAuthnError<Self::TransportError>> {
        let mut req = Ctap2CredentialManagementRequest::new_delete_credential(credential_id);
        loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Preferred,
                &mut req,
                timeout,
            )
            .await?;

            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_credential_management(&req, timeout).await,
                uv_auth_used,
                timeout,
                req
            )
        }?;
        Ok(())
    }

    async fn update_user_info(
        &mut self,
        credential_id: &Ctap2PublicKeyCredentialDescriptor,
        user: &Ctap2PublicKeyCredentialUserEntity,
        timeout: Duration,
    ) -> Result<(), WebAuthnError<Self::TransportError>> {
        let mut req =
            Ctap2CredentialManagementRequest::new_update_user_information(credential_id, user);
        loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Preferred,
                &mut req,
                timeout,
            )
            .await?;

            // Preview mode does not support "updateUserInfo" subcommand
            if req.use_legacy_preview {
                return Err(WebAuthnError::Ctap(CtapError::InvalidCommand));
            }

            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_credential_management(&req, timeout).await,
                uv_auth_used,
                timeout,
                req
            )
        }?;
        Ok(())
    }
}

impl Ctap2UserVerifiableRequest for Ctap2CredentialManagementRequest {
    fn ensure_uv_set(&mut self) {
        // No-op
    }

    fn calculate_and_set_uv_auth(
        &mut self,
        uv_proto: &dyn PinUvAuthProtocol,
        uv_auth_token: &[u8],
    ) -> Result<(), PlatformError> {
        let subcommand = self
            .subcommand
            .ok_or(PlatformError::InvalidDeviceResponse)?;
        let mut data = vec![subcommand as u8];

        // e.g. pinUvAuthParam (0x04): authenticate(pinUvAuthToken, enumerateCredentialsBegin (0x04) || subCommandParams).
        if let Some(params) = &self.subcommand_params {
            data.extend(cbor::to_vec(&params)?);
        }
        let uv_auth_param = uv_proto.authenticate(uv_auth_token, &data)?;
        self.protocol = Some(uv_proto.version());
        self.uv_auth_param = Some(ByteBuf::from(uv_auth_param));
        Ok(())
    }

    fn permissions(&self) -> Ctap2AuthTokenPermissionRole {
        if self.use_persistent_token {
            // pcmr MUST be the sole permission requested (CTAP 2.3-PS 6.5.5.7).
            Ctap2AuthTokenPermissionRole::PERSISTENT_CREDENTIAL_MANAGEMENT_READ_ONLY
        } else {
            Ctap2AuthTokenPermissionRole::CREDENTIAL_MANAGEMENT
        }
    }

    fn permissions_rpid(&self) -> Option<&str> {
        None
    }

    fn can_use_uv(&self, _info: &Ctap2GetInfoResponse) -> bool {
        true
    }

    fn handle_legacy_preview(&mut self, info: &Ctap2GetInfoResponse) {
        if let Some(options) = &info.options {
            // According to Spec, we would also need to verify the token only
            // supports FIDO_2_1_PRE, but let's be a bit less strict here and
            // accept it simply reporting preview-support, but not the real one.
            if options.get("credMgmt") != Some(&true)
                && options.get("credentialMgmtPreview") == Some(&true)
            {
                self.use_legacy_preview = true;
            }
        }
    }

    fn needs_shared_secret(&self, _get_info_response: &Ctap2GetInfoResponse) -> bool {
        false
    }

    fn set_persistent_token_use(&mut self, info: &Ctap2GetInfoResponse, store_available: bool) {
        self.use_persistent_token = store_available
            && info.supports_persistent_credential_management_read_only()
            && self
                .subcommand
                .is_some_and(|subcommand| subcommand.is_read_only());
    }

    fn wants_persistent_token(&self) -> bool {
        self.use_persistent_token
    }

    fn note_persistent_token_rejected(&mut self) {
        self.persistent_token_rejected = true;
    }

    fn persistent_token_rejected(&self) -> bool {
        self.persistent_token_rejected
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use serde_bytes::ByteBuf;
    use serde_indexed::SerializeIndexed;

    use super::CredentialManagement;
    use crate::proto::ctap2::cbor::{self, CborRequest, CborResponse};
    use crate::proto::ctap2::{
        Ctap2CommandCode, Ctap2CredentialManagementRequest, Ctap2GetInfoResponse,
        Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
        Ctap2PublicKeyCredentialType, Ctap2PublicKeyCredentialUserEntity,
    };
    use crate::transport::mock::channel::MockChannel;
    use std::collections::{BTreeMap, HashMap};

    const TIMEOUT: Duration = Duration::from_secs(1);

    // Indexed map enumerateRPs returns: rp (0x03), rpIDHash (0x04), totalRPs (0x05).
    #[derive(SerializeIndexed)]
    struct EnumerateRpsResponse {
        #[serde(index = 0x03)]
        rp: Ctap2PublicKeyCredentialRpEntity,
        #[serde(index = 0x04)]
        rp_id_hash: ByteBuf,
        #[serde(index = 0x05)]
        total_rps: u64,
    }

    // GetInfo for a device without any UV, so user_verification returns without a PIN/UV round-trip.
    fn push_no_uv_get_info(channel: &mut MockChannel) {
        let info = Ctap2GetInfoResponse::default();
        let req = CborRequest::new(Ctap2CommandCode::AuthenticatorGetInfo);
        let resp = CborResponse::new_success_from_slice(&cbor::to_vec(&info).unwrap());
        channel.push_command_pair(req, resp);
    }

    #[tokio::test]
    async fn enumerate_rps_begin_returns_raw_rp_id_hash() {
        let hash = [0xAB_u8; 32];
        let mut channel = MockChannel::new();
        push_no_uv_get_info(&mut channel);

        let req = Ctap2CredentialManagementRequest::new_enumerate_rps_begin();
        let fixture = EnumerateRpsResponse {
            rp: Ctap2PublicKeyCredentialRpEntity::new("example.com", "Example"),
            rp_id_hash: ByteBuf::from(hash.to_vec()),
            total_rps: 1,
        };
        let resp = CborResponse::new_success_from_slice(&cbor::to_vec(&fixture).unwrap());
        channel.push_command_pair((&req).try_into().unwrap(), resp);

        let (rp_data, total) = channel.enumerate_rps_begin(TIMEOUT).await.unwrap();
        assert_eq!(total, 1);
        // Raw 32-byte hash, not a 34-byte CBOR byte string (0x58 0x20 || hash).
        assert_eq!(rp_data.rp_id_hash.len(), 32);
        assert_eq!(rp_data.rp_id_hash, hash.to_vec());
    }

    // GetNextRP returns only rp (0x03) and rpIDHash (0x04).
    #[derive(SerializeIndexed)]
    struct EnumerateRpsNextResponse {
        #[serde(index = 0x03)]
        rp: Ctap2PublicKeyCredentialRpEntity,
        #[serde(index = 0x04)]
        rp_id_hash: ByteBuf,
    }

    // GetNextCredential returns user (0x06), credentialID (0x07), publicKey (0x08), credProtect (0x0A).
    #[derive(SerializeIndexed)]
    struct EnumerateCredsNextResponse {
        #[serde(index = 0x06)]
        user: Ctap2PublicKeyCredentialUserEntity,
        #[serde(index = 0x07)]
        credential_id: Ctap2PublicKeyCredentialDescriptor,
        #[serde(index = 0x08)]
        public_key: BTreeMap<i8, i8>,
        #[serde(index = 0x0A)]
        cred_protect: u64,
    }

    #[tokio::test]
    async fn enumerate_rps_next_rp_sends_only_the_subcommand() {
        let req = Ctap2CredentialManagementRequest::new_enumerate_rps_next_rp();
        let cbor_req: CborRequest = (&req).try_into().unwrap();
        assert_eq!(
            cbor_req.command,
            Ctap2CommandCode::AuthenticatorCredentialManagement
        );
        // CTAP 2.1 §6.8.3: {subCommand: enumerateRPsGetNextRP}, no pinUvAuth keys.
        assert_eq!(cbor_req.encoded_data, vec![0xA1, 0x01, 0x03]);

        let hash = [0xCD_u8; 32];
        let fixture = EnumerateRpsNextResponse {
            rp: Ctap2PublicKeyCredentialRpEntity::new("example.org", "Example"),
            rp_id_hash: ByteBuf::from(hash.to_vec()),
        };
        let resp = CborResponse::new_success_from_slice(&cbor::to_vec(&fixture).unwrap());
        // Queue only the GetNext exchange: any interleaved command panics the mock.
        let mut channel = MockChannel::new();
        channel.push_command_pair(cbor_req, resp);

        let rp_data = channel.enumerate_rps_next_rp(TIMEOUT).await.unwrap();
        assert_eq!(rp_data.rp_id_hash, hash.to_vec());
    }

    #[tokio::test]
    async fn enumerate_credentials_next_sends_only_the_subcommand() {
        let req = Ctap2CredentialManagementRequest::new_enumerate_credentials_next();
        let cbor_req: CborRequest = (&req).try_into().unwrap();
        assert_eq!(
            cbor_req.command,
            Ctap2CommandCode::AuthenticatorCredentialManagement
        );
        // CTAP 2.1 §6.8.4: {subCommand: enumerateCredentialsGetNextCredential}, no pinUvAuth keys.
        assert_eq!(cbor_req.encoded_data, vec![0xA1, 0x01, 0x05]);

        let fixture = EnumerateCredsNextResponse {
            user: Ctap2PublicKeyCredentialUserEntity::new(&[0x0B; 16], "bob", "bob"),
            credential_id: Ctap2PublicKeyCredentialDescriptor {
                id: ByteBuf::from(vec![0x1D; 32]),
                r#type: Ctap2PublicKeyCredentialType::PublicKey,
                transports: None,
            },
            public_key: BTreeMap::from([(1, 2), (3, -7)]),
            cred_protect: 1,
        };
        let resp = CborResponse::new_success_from_slice(&cbor::to_vec(&fixture).unwrap());
        let mut channel = MockChannel::new();
        channel.push_command_pair(cbor_req, resp);

        let cred = channel.enumerate_credentials_next(TIMEOUT).await.unwrap();
        assert_eq!(cred.user.id, ByteBuf::from(vec![0x0B; 16]));
        assert_eq!(cred.cred_protect, 1);
        assert!(cred.large_blob_key.is_none());
    }

    #[tokio::test]
    async fn get_next_reuses_preview_command_resolved_by_begin() {
        let mut channel = MockChannel::new();

        // Device advertises credentialMgmtPreview only: Begin must resolve 0x41.
        let info = Ctap2GetInfoResponse {
            options: Some(HashMap::from([("credentialMgmtPreview".to_string(), true)])),
            ..Default::default()
        };
        let info_req = CborRequest::new(Ctap2CommandCode::AuthenticatorGetInfo);
        let info_resp = CborResponse::new_success_from_slice(&cbor::to_vec(&info).unwrap());
        channel.push_command_pair(info_req, info_resp);

        let mut begin_req = Ctap2CredentialManagementRequest::new_enumerate_rps_begin();
        begin_req.use_legacy_preview = true;
        let begin_cbor: CborRequest = (&begin_req).try_into().unwrap();
        assert_eq!(
            begin_cbor.command,
            Ctap2CommandCode::AuthenticatorCredentialManagementPreview
        );
        let begin_fixture = EnumerateRpsResponse {
            rp: Ctap2PublicKeyCredentialRpEntity::new("example.com", "Example"),
            rp_id_hash: ByteBuf::from(vec![0xEF; 32]),
            total_rps: 2,
        };
        channel.push_command_pair(
            begin_cbor,
            CborResponse::new_success_from_slice(&cbor::to_vec(&begin_fixture).unwrap()),
        );

        let mut next_req = Ctap2CredentialManagementRequest::new_enumerate_rps_next_rp();
        next_req.use_legacy_preview = true;
        let next_cbor: CborRequest = (&next_req).try_into().unwrap();
        assert_eq!(
            next_cbor.command,
            Ctap2CommandCode::AuthenticatorCredentialManagementPreview
        );
        assert_eq!(next_cbor.encoded_data, vec![0xA1, 0x01, 0x03]);
        let next_fixture = EnumerateRpsNextResponse {
            rp: Ctap2PublicKeyCredentialRpEntity::new("example.org", "Example Two"),
            rp_id_hash: ByteBuf::from(vec![0x11; 32]),
        };
        channel.push_command_pair(
            next_cbor,
            CborResponse::new_success_from_slice(&cbor::to_vec(&next_fixture).unwrap()),
        );

        let (_, total) = channel.enumerate_rps_begin(TIMEOUT).await.unwrap();
        assert_eq!(total, 2);
        let rp_data = channel.enumerate_rps_next_rp(TIMEOUT).await.unwrap();
        assert_eq!(rp_data.rp_id_hash, vec![0x11; 32]);
    }
}
