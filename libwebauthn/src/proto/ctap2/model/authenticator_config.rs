use serde::Serialize;
use serde_bytes::ByteBuf;
use serde_indexed::SerializeIndexed;
use serde_repr::{Deserialize_repr, Serialize_repr};

use super::Ctap2PinUvAuthProtocol;

#[derive(Debug, Clone, SerializeIndexed)]
pub struct Ctap2AuthenticatorConfigRequest {
    // subCommand (0x01)
    #[serde(index = 0x01)]
    pub subcommand: Ctap2AuthenticatorConfigCommand,

    // subCommandParams (0x02)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x02)]
    pub subcommand_params: Option<Ctap2AuthenticatorConfigParams>,

    ///pinUvAuthProtocol (0x03)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x03)]
    pub protocol: Option<Ctap2PinUvAuthProtocol>,

    /// pinUvAuthParam (0x04):
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x04)]
    pub uv_auth_param: Option<ByteBuf>,
}

impl Ctap2AuthenticatorConfigRequest {
    pub(crate) fn new_toggle_always_uv() -> Self {
        Ctap2AuthenticatorConfigRequest {
            subcommand: Ctap2AuthenticatorConfigCommand::ToggleAlwaysUv,
            subcommand_params: None,
            protocol: None,      // Will be filled out later by user_verification()
            uv_auth_param: None, // Will be filled out later by user_verification()
        }
    }

    pub(crate) fn new_enable_enterprise_attestation() -> Self {
        Ctap2AuthenticatorConfigRequest {
            subcommand: Ctap2AuthenticatorConfigCommand::EnableEnterpriseAttestation,
            subcommand_params: None,
            protocol: None,      // Will be filled out later by user_verification()
            uv_auth_param: None, // Will be filled out later by user_verification()
        }
    }

    pub(crate) fn new_force_change_pin(force_change_pin: bool) -> Self {
        let subcommand_params =
            Ctap2AuthenticatorConfigParams::SetMinPINLength(Ctap2SetMinPINLengthParams {
                new_min_pin_length: None,
                min_pin_length_rpids: None,
                force_change_pin: Some(force_change_pin),
            });
        Ctap2AuthenticatorConfigRequest {
            subcommand: Ctap2AuthenticatorConfigCommand::SetMinPINLength,
            subcommand_params: Some(subcommand_params),
            protocol: None,      // Will be filled out later by user_verification()
            uv_auth_param: None, // Will be filled out later by user_verification()
        }
    }

    pub(crate) fn new_set_min_pin_length(new_pin_length: u64) -> Self {
        let subcommand_params =
            Ctap2AuthenticatorConfigParams::SetMinPINLength(Ctap2SetMinPINLengthParams {
                new_min_pin_length: Some(new_pin_length),
                min_pin_length_rpids: None,
                force_change_pin: None,
            });
        Ctap2AuthenticatorConfigRequest {
            subcommand: Ctap2AuthenticatorConfigCommand::SetMinPINLength,
            subcommand_params: Some(subcommand_params),
            protocol: None,      // Will be filled out later by user_verification()
            uv_auth_param: None, // Will be filled out later by user_verification()
        }
    }

    pub(crate) fn new_set_min_pin_length_rpids(rpids: Vec<String>) -> Self {
        let subcommand_params =
            Ctap2AuthenticatorConfigParams::SetMinPINLengthRPIDs(Ctap2SetMinPINLengthParams {
                new_min_pin_length: None,
                min_pin_length_rpids: Some(rpids),
                force_change_pin: None,
            });
        Ctap2AuthenticatorConfigRequest {
            subcommand: Ctap2AuthenticatorConfigCommand::SetMinPINLength,
            subcommand_params: Some(subcommand_params),
            protocol: None,      // Will be filled out later by user_verification()
            uv_auth_param: None, // Will be filled out later by user_verification()
        }
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, FromPrimitive, PartialEq, Serialize_repr, Deserialize_repr)]
pub enum Ctap2AuthenticatorConfigCommand {
    EnableEnterpriseAttestation = 0x01,
    ToggleAlwaysUv = 0x02,
    SetMinPINLength = 0x03,
    VendorPrototype = 0xFF,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum Ctap2AuthenticatorConfigParams {
    SetMinPINLength(Ctap2SetMinPINLengthParams),
    SetMinPINLengthRPIDs(Ctap2SetMinPINLengthParams),
}

#[derive(Debug, Clone, SerializeIndexed)]
pub struct Ctap2SetMinPINLengthParams {
    // newMinPINLength (0x01)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x01)]
    pub new_min_pin_length: Option<u64>,

    // minPinLengthRPIDs (0x02)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x02)]
    pub min_pin_length_rpids: Option<Vec<String>>,

    // forceChangePin (0x03)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x03)]
    pub force_change_pin: Option<bool>,
}
