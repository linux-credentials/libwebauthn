use std::fmt::{Debug, Display};
use std::time::Duration;

use crate::proto::ctap2::{
    Ctap2AuthTokenPermissionRole, Ctap2PinUvAuthProtocol, Ctap2UserVerificationOperation,
};
use crate::proto::{
    ctap1::apdu::{ApduRequest, ApduResponse},
    ctap2::cbor::{CborRequest, CborResponse},
};
use crate::webauthn::error::Error;
use crate::UvUpdate;

use async_trait::async_trait;
use cosey::PublicKey;
use tokio::sync::broadcast;
use tracing::{instrument, trace, warn};

use super::device::SupportedProtocols;

#[derive(Debug, Copy, Clone)]
pub enum ChannelStatus {
    Ready, // Channels are created asynchrounously, and are always ready.
    Processing,
    Closed,
}

#[async_trait]
pub trait Channel: Send + Sync + Display + Ctap2AuthTokenStore {
    /// UX updates for this channel, must include UV updates.
    type UxUpdate: Send + Sync + Debug + From<UvUpdate>;

    fn get_ux_update_sender(&self) -> &broadcast::Sender<Self::UxUpdate>;

    fn get_ux_update_receiver(&self) -> broadcast::Receiver<Self::UxUpdate> {
        self.get_ux_update_sender().subscribe()
    }

    #[instrument(skip(self))]
    async fn send_ux_update(&mut self, state: Self::UxUpdate) {
        trace!("Sending UX update");
        match self.get_ux_update_sender().send(state) {
            Ok(_) => (),
            Err(_) => {
                warn!("No receivers for UX update.");
            }
        };
    }

    async fn supported_protocols(&self) -> Result<SupportedProtocols, Error>;
    async fn status(&self) -> ChannelStatus;
    async fn close(&mut self);

    async fn apdu_send(&self, request: &ApduRequest, timeout: Duration) -> Result<(), Error>;
    async fn apdu_recv(&self, timeout: Duration) -> Result<ApduResponse, Error>;

    async fn cbor_send(&mut self, request: &CborRequest, timeout: Duration) -> Result<(), Error>;
    async fn cbor_recv(&mut self, timeout: Duration) -> Result<CborResponse, Error>;

    /// Allows channels to disable support for pre-flight requests
    fn supports_preflight() -> bool {
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ctap2AuthTokenPermission {
    pub(crate) pin_uv_auth_protocol: Ctap2PinUvAuthProtocol,
    pub(crate) role: Ctap2AuthTokenPermissionRole,
    pub(crate) rpid: Option<String>,
}

impl Ctap2AuthTokenPermission {
    pub fn new(
        pin_uv_auth_protocol: Ctap2PinUvAuthProtocol,
        permissions: Ctap2AuthTokenPermissionRole,
        permissions_rpid: Option<&str>,
    ) -> Self {
        Self {
            pin_uv_auth_protocol,
            role: permissions,
            rpid: permissions_rpid.map(str::to_string),
        }
    }

    pub fn contains(&self, requested: &Ctap2AuthTokenPermission) -> bool {
        if self.pin_uv_auth_protocol != requested.pin_uv_auth_protocol {
            return false;
        }
        if self.rpid != requested.rpid {
            return false;
        }
        self.role.contains(requested.role)
    }
}

#[derive(Debug, Clone)]
pub struct AuthTokenData {
    pub shared_secret: Vec<u8>,
    pub permission: Ctap2AuthTokenPermission,
    pub pin_uv_auth_token: Vec<u8>,
    pub protocol_version: Ctap2PinUvAuthProtocol,
    pub key_agreement: PublicKey,
    pub uv_operation: Ctap2UserVerificationOperation,
}

#[async_trait]
pub trait Ctap2AuthTokenStore {
    fn store_auth_data(&mut self, auth_token_data: AuthTokenData);
    fn get_auth_data(&self) -> Option<&AuthTokenData>;
    fn clear_uv_auth_token_store(&mut self);
    fn get_uv_auth_token(&self, requested_permission: &Ctap2AuthTokenPermission) -> Option<&[u8]> {
        if let Some(stored_data) = self.get_auth_data() {
            if stored_data.permission.contains(requested_permission) {
                return Some(&stored_data.pin_uv_auth_token);
            }
        }
        None
    }
    fn used_pin_for_auth(&self) -> bool {
        if let Some(stored_data) = self.get_auth_data() {
            return stored_data.uv_operation
                == Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingPinWithPermissions
                || stored_data.uv_operation == Ctap2UserVerificationOperation::GetPinToken;
        }
        false
    }
}
