use std::collections::HashMap;

use serde_bytes::ByteBuf;
use serde_indexed::DeserializeIndexed;
use tracing::debug;

use super::{Ctap2CredentialType, Ctap2UserVerificationOperation};

#[derive(Debug, Clone, DeserializeIndexed, Default)]
pub struct Ctap2GetInfoResponse {
    /// versions (0x01)
    #[serde(index = 0x01)]
    pub versions: Vec<String>,

    /// extensions (0x02)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x02)]
    pub extensions: Option<Vec<String>>,

    /// aaguid (0x03)
    #[serde(index = 0x03)]
    pub aaguid: ByteBuf,

    /// options (0x04)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x04)]
    pub options: Option<HashMap<String, bool>>,

    /// maxMsgSize (0x05)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x05)]
    pub max_msg_size: Option<u32>,

    /// pinUvAuthProtocols (0x06)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x06)]
    pub pin_auth_protos: Option<Vec<u32>>,

    /// maxCredentialCountInList (0x07)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x07)]
    pub max_credential_count: Option<u32>,

    /// maxCredentialIdLength (0x08)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x08)]
    pub max_credential_id_length: Option<u32>,

    /// transports (0x09)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x09)]
    pub transports: Option<Vec<String>>,

    /// algorithms (0x0A)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x0A)]
    pub algorithms: Option<Vec<Ctap2CredentialType>>,

    /// maxSerializedLargeBlobArray (0x0B)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x0B)]
    pub max_blob_array: Option<u32>,

    /// forcePINChange (0x0C)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x0C)]
    pub force_pin_change: Option<bool>,

    /// minPINLength (0x0D)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x0D)]
    pub min_pin_length: Option<u32>,

    /// firmwareVersion (0x0E)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x0E)]
    pub firmware_version: Option<u32>,

    /// maxCredBlobLength (0x0F)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x0F)]
    pub max_cred_blob_length: Option<u32>,

    /// maxRPIDsForSetMinPINLength (0x10)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x10)]
    pub max_rpids_for_setminpinlength: Option<u32>,

    /// preferredPlatformUvAttempts (0x11)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x11)]
    pub preferred_platform_uv_attempts: Option<u32>,

    /// uvModality (0x12)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x12)]
    pub uv_modality: Option<u32>,

    /// certifications (0x13)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x13)]
    pub certifications: Option<HashMap<String, u32>>,

    /// remainingDiscoverableCredentials (0x14)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x14)]
    pub remaining_discoverable_creds: Option<u32>,

    /// vendorPrototypeConfigCommands (0x15)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x15)]
    pub vendor_proto_config_cmds: Option<Vec<u32>>,

    /// attestationFormats (0x16)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x16)]
    pub attestation_formats: Option<Vec<String>>,

    /// uvCountSinceLastPinEntry (0x17)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x17)]
    pub uv_count_since_last_pin_entry: Option<u32>,

    /// longTouchForReset (0x18)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x18)]
    pub long_touch_for_reset: Option<bool>,

    /// encIdentifier (0x19)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x19)]
    pub enc_identifier: Option<ByteBuf>,

    /// transportsForReset (0x1A)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x1A)]
    pub transports_for_reset: Option<Vec<String>>,

    /// pinComplexityPolicy (0x1B)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x1B)]
    pub pin_complexity_policy: Option<bool>,

    /// pinComplexityPolicyURL (0x1C)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x1C)]
    pub pin_complexity_policy_url: Option<ByteBuf>,

    /// maxPINLength (0x1D)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x1D)]
    pub max_pin_length: Option<u32>,
}

impl Ctap2GetInfoResponse {
    /// Only checks if the option exists, i.e. is not None
    /// but does not check if the option is enabled (true)
    /// or disabled (false)
    pub fn option_exists(&self, name: &str) -> bool {
        let Some(options) = self.options.as_ref() else {
            return false;
        };
        options.get(name).is_some()
    }

    /// Checks if the option exists and is set to true
    pub fn option_enabled(&self, name: &str) -> bool {
        let Some(options) = self.options.as_ref() else {
            return false;
        };
        options.get(name) == Some(&true)
    }

    pub fn supports_fido_2_1(&self) -> bool {
        self.versions.iter().any(|v| v == "FIDO_2_1")
    }

    pub fn supports_credential_management(&self) -> bool {
        self.option_enabled("credMgmt") || self.option_enabled("credentialMgmtPreview")
    }

    pub fn supports_bio_enrollment(&self) -> bool {
        if let Some(options) = &self.options {
            return options.get("bioEnroll").is_some()
                || options.get("userVerificationMgmtPreview").is_some();
        }
        false
    }

    pub fn has_bio_enrollments(&self) -> bool {
        if let Some(options) = &self.options {
            return options.get("bioEnroll") == Some(&true)
                || options.get("userVerificationMgmtPreview") == Some(&true);
        }
        false
    }

    /// Implements check for "Protected by some form of User Verification":
    ///   Either or both clientPin or built-in user verification methods are supported and enabled.
    ///   I.e., in the authenticatorGetInfo response the pinUvAuthToken option ID is present and set to true,
    ///   and either clientPin option ID is present and set to true or uv option ID is present and set to true or both.
    pub fn is_uv_protected(&self) -> bool {
        self.option_enabled("uv") || // Deprecated no-op UV
            self.option_enabled("clientPin") ||
            (self.option_enabled("pinUvAuthToken") && self.option_enabled("uv"))
    }

    pub fn can_establish_shared_secret(&self) -> bool {
        // clientPin exists: clientPin command is supported, so we can establish a shared secret
        // uv exists and pinUvAuthToken is enabled: clientPin command partially supported. Enough to establish shared secret
        self.option_exists("clientPin")
            || (self.option_exists("uv") && self.option_enabled("pinUvAuthToken"))
    }

    pub fn uv_operation(&self, uv_blocked: bool) -> Option<Ctap2UserVerificationOperation> {
        if self.option_enabled("uv") && !uv_blocked {
            if self.option_enabled("pinUvAuthToken") {
                debug!("getPinUvAuthTokenUsingUvWithPermissions");
                Some(Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingUvWithPermissions)
            } else {
                debug!("Deprecated FIDO 2.0 behaviour: populating 'uv' flag");
                Some(Ctap2UserVerificationOperation::LegacyUv)
            }
        } else {
            // !uv

            // clientPIN exists, but is not enabled, aka PIN is not yet set on the device
            // We can use it for establishing a shared secret, but not for creating a pinUvAuthToken
            if self.option_exists("clientPin") && !self.option_enabled("clientPin") {
                return Some(Ctap2UserVerificationOperation::ClientPinOnlyForSharedSecret);
            }

            // clientPin is not enabled (not supported or Pin not set) and
            // UV + pinUvAuthToken is supported, but UV is blocked (maybe too many retries)
            // or it is not set yet.
            // We can still use it for establishing a shared secret, but not for creating a pinUvAuthToken
            if !self.option_enabled("clientPin")
                && self.option_exists("uv")
                && self.option_enabled("pinUvAuthToken")
            {
                return Some(Ctap2UserVerificationOperation::ClientPinOnlyForSharedSecret);
            }

            // If we do have a PIN, check if we need to use legacy getPinToken or new getPinUvAuthToken..-command
            if self.option_enabled("pinUvAuthToken") {
                assert!(self.option_enabled("clientPin"));
                debug!("getPinUvAuthTokenUsingPinWithPermissions");
                Some(Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingPinWithPermissions)
            } else if self.option_enabled("clientPin") {
                // !pinUvAuthToken
                debug!("getPinToken");
                Some(Ctap2UserVerificationOperation::GetPinToken)
            } else {
                debug!("No UV and no PIN (e.g. maybe UV was blocked and no PIN available)");
                None
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use crate::proto::ctap2::Ctap2UserVerificationOperation;

    use super::Ctap2GetInfoResponse;

    fn create_info(options: &[(&str, bool)]) -> Ctap2GetInfoResponse {
        let mut info = Ctap2GetInfoResponse::default();
        let mut input = HashMap::new();
        for (key, val) in options {
            input.insert(key.to_string(), *val);
        }
        info.options = Some(input);
        info
    }

    #[test]
    fn device_no_options() {
        let info = Ctap2GetInfoResponse::default();
        assert!(!info.supports_fido_2_1());
        assert!(!info.supports_credential_management());
        assert!(!info.supports_bio_enrollment());
        assert!(!info.is_uv_protected());
        assert!(!info.can_establish_shared_secret());
        assert_eq!(info.uv_operation(false), None);
        assert_eq!(info.uv_operation(true), None);
    }

    #[test]
    fn device_empty_options() {
        let info = create_info(&[]);
        assert!(!info.supports_fido_2_1());
        assert!(!info.supports_credential_management());
        assert!(!info.supports_bio_enrollment());
        assert!(!info.is_uv_protected());
        assert!(!info.can_establish_shared_secret());
        assert_eq!(info.uv_operation(false), None);
        assert_eq!(info.uv_operation(true), None);
    }

    #[test]
    fn device_legacy_uv() {
        // Support legacy UV of CTAP2.0
        // Meaning: "uv" option is supported, but not clientPin or pinUvAuthToken
        // So, it supports built in UV, but no way to establish a pinUvAuthToken or shared secret
        let info = create_info(&[("uv", true)]);
        assert!(info.is_uv_protected());
        assert!(!info.can_establish_shared_secret());
        assert_eq!(
            info.uv_operation(false),
            Some(Ctap2UserVerificationOperation::LegacyUv)
        );
        // If UV is blocked, no other option is available
        assert_eq!(info.uv_operation(true), None);
    }

    #[test]
    fn device_legacy_uv_but_not_set() {
        // Support legacy UV of CTAP2.0, but not activated yet
        let info = create_info(&[("uv", false)]);
        // We are currently NOT protected
        assert!(!info.is_uv_protected());
        assert!(!info.can_establish_shared_secret());
        assert_eq!(info.uv_operation(false), None);
        assert_eq!(info.uv_operation(true), None);
    }

    #[test]
    fn device_ctap20_pin_only() {
        // Support CTAP 2.0 PIN operation
        // Meaning: "clientPin", but not "pinUvAuthToken"
        let info = create_info(&[("clientPin", true)]);
        assert!(info.is_uv_protected());
        assert!(info.can_establish_shared_secret());
        assert_eq!(
            info.uv_operation(false),
            Some(Ctap2UserVerificationOperation::GetPinToken)
        );
        assert_eq!(
            info.uv_operation(true),
            Some(Ctap2UserVerificationOperation::GetPinToken)
        );
    }

    #[test]
    fn device_ctap20_pin_only_but_not_set() {
        // Support CTAP 2.0 PIN operation
        // Meaning: "clientPin", but not "pinUvAuthToken", but the Pin is not set
        let info = create_info(&[("clientPin", false)]);
        // We are currently NOT protected
        assert!(!info.is_uv_protected());
        // We CAN establish a shared secret this way
        assert!(info.can_establish_shared_secret());
        assert_eq!(
            info.uv_operation(false),
            Some(Ctap2UserVerificationOperation::ClientPinOnlyForSharedSecret)
        );
        assert_eq!(
            info.uv_operation(true),
            Some(Ctap2UserVerificationOperation::ClientPinOnlyForSharedSecret)
        );
    }

    #[test]
    fn device_ctap20_pin_and_uv() {
        // Support CTAP 2.0 PIN operation and CTAP 2.0 UV
        // Meaning: "clientPin" and "uv"
        let info = create_info(&[("clientPin", true), ("uv", true)]);
        assert!(info.is_uv_protected());
        assert!(info.can_establish_shared_secret());
        assert_eq!(
            info.uv_operation(false),
            Some(Ctap2UserVerificationOperation::LegacyUv)
        );
        assert_eq!(
            info.uv_operation(true),
            Some(Ctap2UserVerificationOperation::GetPinToken)
        );
    }

    #[test]
    fn device_ctap20_pin_and_uv_but_only_pin_set() {
        // Support CTAP 2.0 PIN operation and CTAP 2.0 UV
        // Meaning: "clientPin" and "uv"
        let info = create_info(&[("clientPin", true), ("uv", false)]);
        assert!(info.is_uv_protected());
        assert!(info.can_establish_shared_secret());
        assert_eq!(
            info.uv_operation(false),
            Some(Ctap2UserVerificationOperation::GetPinToken)
        );
        assert_eq!(
            info.uv_operation(true),
            Some(Ctap2UserVerificationOperation::GetPinToken)
        );
    }

    #[test]
    fn device_ctap20_pin_and_uv_but_only_uv_set() {
        // Support CTAP 2.0 PIN operation and CTAP 2.0 UV
        // Meaning: "clientPin" and "uv"
        let info = create_info(&[("clientPin", false), ("uv", true)]);
        assert!(info.is_uv_protected());
        assert!(info.can_establish_shared_secret());
        assert_eq!(
            info.uv_operation(false),
            Some(Ctap2UserVerificationOperation::LegacyUv)
        );
        assert_eq!(
            info.uv_operation(true),
            Some(Ctap2UserVerificationOperation::ClientPinOnlyForSharedSecret)
        );
    }

    #[test]
    fn device_ctap20_pin_and_uv_but_neither_set() {
        // Support CTAP 2.0 PIN operation and CTAP 2.0 UV
        // Meaning: "clientPin" and "uv"
        let info = create_info(&[("clientPin", false), ("uv", false)]);
        // We are currently NOT protected
        assert!(!info.is_uv_protected());
        // But we should be able to establish a shared secret
        assert!(info.can_establish_shared_secret());
        assert_eq!(
            info.uv_operation(false),
            Some(Ctap2UserVerificationOperation::ClientPinOnlyForSharedSecret)
        );
        assert_eq!(
            info.uv_operation(true),
            Some(Ctap2UserVerificationOperation::ClientPinOnlyForSharedSecret)
        );
    }

    #[test]
    fn device_ctap21_pin_only() {
        // Support CTAP 2.1 PIN operation
        // Meaning: "clientPin" and "pinUvAuthToken"
        let info = create_info(&[("clientPin", true), ("pinUvAuthToken", true)]);
        assert!(info.is_uv_protected());
        assert!(info.can_establish_shared_secret());
        assert_eq!(
            info.uv_operation(false),
            Some(Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingPinWithPermissions)
        );
        assert_eq!(
            info.uv_operation(true),
            Some(Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingPinWithPermissions)
        );
    }

    #[test]
    fn device_ctap21_uv_only() {
        // Support CTAP 2.1 UV operation
        // Meaning: "uv" and "pinUvAuthToken"
        let info = create_info(&[("uv", true), ("pinUvAuthToken", true)]);
        assert!(info.is_uv_protected());
        assert!(info.can_establish_shared_secret());
        assert_eq!(
            info.uv_operation(false),
            Some(Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingUvWithPermissions)
        );
        assert_eq!(
            info.uv_operation(true),
            Some(Ctap2UserVerificationOperation::ClientPinOnlyForSharedSecret)
        );
    }

    #[test]
    fn device_ctap21_pin_and_uv() {
        // Support CTAP 2.1 PIN+UV operation
        // Meaning: "clientPin", "uv" and "pinUvAuthToken"
        let info = create_info(&[("clientPin", true), ("uv", true), ("pinUvAuthToken", true)]);
        assert!(info.is_uv_protected());
        assert!(info.can_establish_shared_secret());
        assert_eq!(
            info.uv_operation(false),
            Some(Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingUvWithPermissions)
        );
        assert_eq!(
            info.uv_operation(true),
            Some(Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingPinWithPermissions)
        );
    }

    #[test]
    fn device_ctap21_pin_only_but_not_set() {
        // Support CTAP 2.1 PIN operation
        // Meaning: "clientPin" and "pinUvAuthToken", but Pin not set
        let info = create_info(&[("clientPin", false), ("pinUvAuthToken", true)]);
        // We are currently NOT protected
        assert!(!info.is_uv_protected());
        // But we should be able to establish a shared secret
        assert!(info.can_establish_shared_secret());
        assert_eq!(
            info.uv_operation(false),
            Some(Ctap2UserVerificationOperation::ClientPinOnlyForSharedSecret)
        );
        assert_eq!(
            info.uv_operation(true),
            Some(Ctap2UserVerificationOperation::ClientPinOnlyForSharedSecret)
        );
    }

    #[test]
    fn device_ctap21_uv_only_but_not_set() {
        // Support CTAP 2.1 UV operation
        let info = create_info(&[("uv", false), ("pinUvAuthToken", true)]);
        // We are currently NOT protected
        assert!(!info.is_uv_protected());
        // But we should be able to establish a shared secret
        assert!(info.can_establish_shared_secret());
        assert_eq!(
            info.uv_operation(false),
            Some(Ctap2UserVerificationOperation::ClientPinOnlyForSharedSecret)
        );
        assert_eq!(
            info.uv_operation(true),
            Some(Ctap2UserVerificationOperation::ClientPinOnlyForSharedSecret)
        );
    }

    #[test]
    fn device_ctap21_pin_and_uv_but_only_pin_set() {
        let info = create_info(&[("clientPin", true), ("uv", false), ("pinUvAuthToken", true)]);
        assert!(info.is_uv_protected());
        assert!(info.can_establish_shared_secret());
        assert_eq!(
            info.uv_operation(false),
            Some(Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingPinWithPermissions)
        );
        assert_eq!(
            info.uv_operation(true),
            Some(Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingPinWithPermissions)
        );
    }

    #[test]
    fn device_ctap21_pin_and_uv_but_only_uv_set() {
        let info = create_info(&[("clientPin", false), ("uv", true), ("pinUvAuthToken", true)]);
        assert!(info.is_uv_protected());
        assert!(info.can_establish_shared_secret());
        assert_eq!(
            info.uv_operation(false),
            Some(Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingUvWithPermissions)
        );
        assert_eq!(
            info.uv_operation(true),
            Some(Ctap2UserVerificationOperation::ClientPinOnlyForSharedSecret)
        );
    }

    #[test]
    fn device_ctap21_pin_and_uv_but_neither_set() {
        let info = create_info(&[
            ("clientPin", false),
            ("uv", false),
            ("pinUvAuthToken", true),
        ]);
        // We are currently NOT protected
        assert!(!info.is_uv_protected());
        // But we should be able to establish a shared secret
        assert!(info.can_establish_shared_secret());
        assert_eq!(
            info.uv_operation(false),
            Some(Ctap2UserVerificationOperation::ClientPinOnlyForSharedSecret)
        );
        assert_eq!(
            info.uv_operation(true),
            Some(Ctap2UserVerificationOperation::ClientPinOnlyForSharedSecret)
        );
    }
}
