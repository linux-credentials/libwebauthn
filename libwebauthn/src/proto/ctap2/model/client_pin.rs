use cosey::PublicKey;
use serde_bytes::ByteBuf;
use serde_indexed::{DeserializeIndexed, SerializeIndexed};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::pin::{PinUvAuthProtocol, PinUvAuthProtocolOne, PinUvAuthProtocolTwo};

#[derive(Debug, Clone, SerializeIndexed)]
pub struct Ctap2ClientPinRequest {
    ///pinUvAuthProtocol (0x01)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x01)]
    pub protocol: Option<Ctap2PinUvAuthProtocol>,

    /// subCommand (0x02)
    #[serde(index = 0x02)]
    pub command: Ctap2PinUvAuthProtocolCommand,

    /// keyAgreement (0x03)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x03)]
    pub key_agreement: Option<PublicKey>,

    /// pinUvAuthParam (0x04):
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x04)]
    pub uv_auth_param: Option<ByteBuf>,

    /// newPinEnc (0x05)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x05)]
    pub new_pin_encrypted: Option<ByteBuf>,

    /// pinHashEnc (0x06)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x06)]
    pub pin_hash_encrypted: Option<ByteBuf>,

    /// permissions (0x09)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x09)]
    pub permissions: Option<u32>,

    /// permissions RPID (0x0A)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x0A)]
    pub permissions_rpid: Option<String>,
}

impl Ctap2ClientPinRequest {
    pub fn new_get_key_agreement(protocol: Ctap2PinUvAuthProtocol) -> Self {
        Self {
            protocol: Some(protocol),
            command: Ctap2PinUvAuthProtocolCommand::GetKeyAgreement,
            key_agreement: None,
            uv_auth_param: None,
            new_pin_encrypted: None,
            pin_hash_encrypted: None,
            permissions: None,
            permissions_rpid: None,
        }
    }

    pub fn new_get_pin_token(
        protocol: Ctap2PinUvAuthProtocol,
        public_key: PublicKey,
        pin_hash_enc: &[u8],
    ) -> Self {
        Self {
            protocol: Some(protocol),
            command: Ctap2PinUvAuthProtocolCommand::GetPinToken,
            key_agreement: Some(public_key),
            uv_auth_param: None,
            new_pin_encrypted: None,
            pin_hash_encrypted: Some(ByteBuf::from(pin_hash_enc)),
            permissions: None,
            permissions_rpid: None,
        }
    }

    pub fn new_get_pin_retries(pin_proto: Option<Ctap2PinUvAuthProtocol>) -> Self {
        Self {
            protocol: pin_proto,
            command: Ctap2PinUvAuthProtocolCommand::GetPinRetries,
            key_agreement: None,
            uv_auth_param: None,
            new_pin_encrypted: None,
            pin_hash_encrypted: None,
            permissions: None,
            permissions_rpid: None,
        }
    }

    pub fn new_get_pin_token_with_perm(
        protocol: Ctap2PinUvAuthProtocol,
        public_key: PublicKey,
        pin_hash_enc: &[u8],
        permissions: Ctap2AuthTokenPermissionRole,
        permissions_rpid: Option<&str>,
    ) -> Self {
        Self {
            protocol: Some(protocol),
            command: Ctap2PinUvAuthProtocolCommand::GetPinUvAuthTokenUsingPinWithPermissions,
            key_agreement: Some(public_key),
            uv_auth_param: None,
            new_pin_encrypted: None,
            pin_hash_encrypted: Some(ByteBuf::from(pin_hash_enc)),
            permissions: Some(permissions.bits()),
            permissions_rpid: permissions_rpid.map(str::to_owned),
        }
    }

    pub fn new_get_uv_token_with_perm(
        protocol: Ctap2PinUvAuthProtocol,
        public_key: PublicKey,
        permissions: Ctap2AuthTokenPermissionRole,
        permissions_rpid: Option<&str>,
    ) -> Self {
        Self {
            protocol: Some(protocol),
            command: Ctap2PinUvAuthProtocolCommand::GetPinUvAuthTokenUsingUvWithPermissions,
            key_agreement: Some(public_key),
            uv_auth_param: None,
            new_pin_encrypted: None,
            pin_hash_encrypted: None,
            permissions: Some(permissions.bits()),
            permissions_rpid: permissions_rpid.map(str::to_owned),
        }
    }

    pub fn new_get_uv_retries() -> Self {
        Self {
            // GetUvRetries never needed the protocol sent. GetPINRetries did for CTAP 2.0
            protocol: None,
            command: Ctap2PinUvAuthProtocolCommand::GetUvRetries,
            key_agreement: None,
            uv_auth_param: None,
            new_pin_encrypted: None,
            pin_hash_encrypted: None,
            permissions: None,
            permissions_rpid: None,
        }
    }

    pub fn new_change_pin(
        protocol: Ctap2PinUvAuthProtocol,
        new_pin_enc: &[u8],
        curr_pin_enc: &[u8],
        public_key: PublicKey,
        uv_auth_param: &[u8],
    ) -> Self {
        Self {
            protocol: Some(protocol),
            command: Ctap2PinUvAuthProtocolCommand::ChangePin,
            key_agreement: Some(public_key),
            uv_auth_param: Some(ByteBuf::from(uv_auth_param)),
            new_pin_encrypted: Some(ByteBuf::from(new_pin_enc)),
            pin_hash_encrypted: Some(ByteBuf::from(curr_pin_enc)),
            permissions: None,
            permissions_rpid: None,
        }
    }

    pub fn new_set_pin(
        protocol: Ctap2PinUvAuthProtocol,
        new_pin_enc: &[u8],
        public_key: PublicKey,
        uv_auth_param: &[u8],
    ) -> Self {
        Self {
            protocol: Some(protocol),
            command: Ctap2PinUvAuthProtocolCommand::SetPin,
            key_agreement: Some(public_key),
            uv_auth_param: Some(ByteBuf::from(uv_auth_param)),
            new_pin_encrypted: Some(ByteBuf::from(new_pin_enc)),
            pin_hash_encrypted: None,
            permissions: None,
            permissions_rpid: None,
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Ctap2AuthTokenPermissionRole: u32 {
        const MAKE_CREDENTIAL = 0x01;
        const GET_ASSERTION = 0x02;
        const CREDENTIAL_MANAGEMENT = 0x04;
        const BIO_ENROLLMENT = 0x08;
        const LARGE_BLOB_WRITE = 0x10;
        const AUTHENTICATOR_CONFIGURATION = 0x20;
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, FromPrimitive, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
pub enum Ctap2PinUvAuthProtocol {
    One = 1,
    Two = 2,
}

impl Ctap2PinUvAuthProtocol {
    pub(crate) fn create_protocol_object(&self) -> Box<dyn PinUvAuthProtocol> {
        match self {
            Ctap2PinUvAuthProtocol::One => Box::new(PinUvAuthProtocolOne::new()),
            Ctap2PinUvAuthProtocol::Two => Box::new(PinUvAuthProtocolTwo::new()),
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, FromPrimitive, PartialEq, Serialize_repr, Deserialize_repr)]
pub enum Ctap2PinUvAuthProtocolCommand {
    GetPinRetries = 0x01,
    GetKeyAgreement = 0x02,
    SetPin = 0x03,
    ChangePin = 0x04,
    GetPinToken = 0x05,
    GetPinUvAuthTokenUsingUvWithPermissions = 0x06,
    GetUvRetries = 0x07,
    GetPinUvAuthTokenUsingPinWithPermissions = 0x09,
}

#[cfg_attr(test, derive(SerializeIndexed))]
#[derive(Debug, Clone, Default, DeserializeIndexed)]
pub struct Ctap2ClientPinResponse {
    /// keyAgreement (0x01)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x01)]
    pub key_agreement: Option<PublicKey>,

    /// pinUvAuthToken (0x02)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x02)]
    pub pin_uv_auth_token: Option<ByteBuf>,

    /// pinRetries (0x03)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x03)]
    pub pin_retries: Option<u32>,

    /// powerCycleState (0x04)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x04)]
    pub power_cycle_state: Option<bool>,

    /// uvRetries (0x05)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x05)]
    pub uv_retries: Option<u32>,
}
