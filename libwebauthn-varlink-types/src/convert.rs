use libwebauthn::{
    ops::webauthn::{Origin, OriginParseError, RequestOrigin as LibRequestOrigin},
    pin::{PinNotSetReason, PinRequestReason},
    transport::cable::qr_code_device::{CableTransports, QrCodeOperationHint},
    PinNotSetUpdate, PinRequiredUpdate,
};
use serde::{Deserialize, Serialize};
use zlink::introspect;

/// Plain origin string for a WebAuthn request, as supplied by the client.
#[derive(Debug, Clone, Serialize, Deserialize, introspect::CustomType)]
#[zlink(rename = "RequestOrigin")]
pub struct VarlinkRequestOrigin {
    pub origin: String,
    pub top_origin: Option<String>,
}

impl TryFrom<&str> for VarlinkRequestOrigin {
    type Error = OriginParseError;

    fn try_from(origin: &str) -> Result<Self, Self::Error> {
        let parsed: Origin = origin.parse()?;
        Ok(VarlinkRequestOrigin {
            origin: parsed.to_string(),
            top_origin: None,
        })
    }
}

impl TryFrom<VarlinkRequestOrigin> for LibRequestOrigin {
    type Error = OriginParseError;

    fn try_from(req_origin: VarlinkRequestOrigin) -> Result<Self, Self::Error> {
        let origin: Origin = req_origin.origin.parse()?;
        let top_origin = req_origin.top_origin.map(|o| o.parse()).transpose()?;
        Ok(LibRequestOrigin { origin, top_origin })
    }
}

/// The ceremony a hybrid QR code is generated for. The phone uses it to
/// decide how to present the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
#[zlink(rename = "Operation")]
pub enum VarlinkOperation {
    MakeCredential,
    GetAssertion,
}

impl From<VarlinkOperation> for QrCodeOperationHint {
    fn from(operation: VarlinkOperation) -> Self {
        match operation {
            VarlinkOperation::MakeCredential => QrCodeOperationHint::MakeCredential,
            VarlinkOperation::GetAssertion => QrCodeOperationHint::GetAssertionRequest,
        }
    }
}

/// Which hybrid transport(s) to use/advertise in the QR code.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, introspect::CustomType)]
#[zlink(rename = "TransportMode")]
pub enum VarlinkTransportMode {
    /// Cloud-assisted WebSocket tunnel only.
    CloudOnly,
    /// Cloud-assisted tunnel plus the direct BLE data channel (CTAP 2.3 hybrid).
    CloudOrBle,
}

impl From<VarlinkTransportMode> for CableTransports {
    fn from(mode: VarlinkTransportMode) -> Self {
        match mode {
            VarlinkTransportMode::CloudOnly => CableTransports::CloudAssistedOnly,
            VarlinkTransportMode::CloudOrBle => CableTransports::CloudAssistedOrLocal,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, introspect::CustomType)]
#[zlink(rename = "PinRequired")]
pub struct VarlinkPinRequired {
    pub attempts_left: Option<i64>,
    pub reason: VarlinkPinRequestReason,
}

#[derive(Debug, Clone, Serialize, Deserialize, introspect::CustomType)]
#[zlink(rename = "PinNotSet")]
pub struct VarlinkPinNotSet {
    pub reason: VarlinkPinNotSetReason,
}

impl From<PinNotSetUpdate> for VarlinkPinNotSet {
    fn from(update: PinNotSetUpdate) -> Self {
        VarlinkPinNotSet {
            reason: update.reason.into(),
        }
    }
}

impl From<PinRequiredUpdate> for VarlinkPinRequired {
    fn from(update: PinRequiredUpdate) -> Self {
        VarlinkPinRequired {
            attempts_left: update.attempts_left.map(|a| a as i64),
            reason: update.reason.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, introspect::CustomType)]
#[zlink(rename = "PinRequestReason")]
pub enum VarlinkPinRequestReason {
    AuthenticatorPolicy,
    FallbackFromUV,
    RelyingPartyRequest,
}

impl From<PinRequestReason> for VarlinkPinRequestReason {
    fn from(reason: PinRequestReason) -> Self {
        match reason {
            PinRequestReason::AuthenticatorPolicy => VarlinkPinRequestReason::AuthenticatorPolicy,
            PinRequestReason::FallbackFromUV => VarlinkPinRequestReason::FallbackFromUV,
            PinRequestReason::RelyingPartyRequest => VarlinkPinRequestReason::RelyingPartyRequest,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, introspect::CustomType)]
#[zlink(rename = "PinNotSetReason")]
pub enum VarlinkPinNotSetReason {
    PinChangeRequired,
    PinNotSet,
    PinPolicyViolation,
    PinTooLong,
    PinTooShort,
}

impl From<PinNotSetReason> for VarlinkPinNotSetReason {
    fn from(reason: PinNotSetReason) -> Self {
        match reason {
            PinNotSetReason::PinChangeRequired => VarlinkPinNotSetReason::PinChangeRequired,
            PinNotSetReason::PinNotSet => VarlinkPinNotSetReason::PinNotSet,
            PinNotSetReason::PinPolicyViolation => VarlinkPinNotSetReason::PinPolicyViolation,
            PinNotSetReason::PinTooLong => VarlinkPinNotSetReason::PinTooLong,
            PinNotSetReason::PinTooShort => VarlinkPinNotSetReason::PinTooShort,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, introspect::CustomType)]
#[zlink(rename = "Retry")]
pub struct VarlinkRetry {
    pub attempts_left: Option<u32>,
}

impl From<Option<u32>> for VarlinkRetry {
    fn from(attempts_left: Option<u32>) -> Self {
        VarlinkRetry { attempts_left }
    }
}

impl From<u32> for VarlinkRetry {
    fn from(value: u32) -> Self {
        VarlinkRetry {
            attempts_left: Some(value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_origin_is_parsed_and_normalized() {
        let origin = VarlinkRequestOrigin::try_from("HTTPS://Example.org").unwrap();
        assert_eq!(origin.origin, "https://example.org");
        assert_eq!(origin.top_origin, None);
    }

    #[test]
    fn malformed_request_origin_is_rejected() {
        assert!(VarlinkRequestOrigin::try_from("not an origin").is_err());
    }

    #[test]
    fn request_origin_converts_with_top_origin() {
        let origin = LibRequestOrigin::try_from(VarlinkRequestOrigin {
            origin: "https://example.org".into(),
            top_origin: Some("https://top.example.org".into()),
        })
        .unwrap();
        assert_eq!(origin.origin.to_string(), "https://example.org");
        assert_eq!(
            origin.top_origin.map(|o| o.to_string()).as_deref(),
            Some("https://top.example.org")
        );
    }

    #[test]
    fn malformed_top_origin_is_rejected() {
        assert!(LibRequestOrigin::try_from(VarlinkRequestOrigin {
            origin: "https://example.org".into(),
            top_origin: Some("not an origin".into()),
        })
        .is_err());
    }

    #[test]
    fn operation_maps_to_qr_code_hint() {
        assert_eq!(
            QrCodeOperationHint::from(VarlinkOperation::MakeCredential),
            QrCodeOperationHint::MakeCredential
        );
        assert_eq!(
            QrCodeOperationHint::from(VarlinkOperation::GetAssertion),
            QrCodeOperationHint::GetAssertionRequest
        );
    }

    #[test]
    fn transport_mode_maps_to_cable_transports() {
        assert_eq!(
            CableTransports::from(VarlinkTransportMode::CloudOnly),
            CableTransports::CloudAssistedOnly
        );
        assert_eq!(
            CableTransports::from(VarlinkTransportMode::CloudOrBle),
            CableTransports::CloudAssistedOrLocal
        );
    }

    #[test]
    fn pin_request_reasons_map_one_to_one() {
        assert!(matches!(
            PinRequestReason::AuthenticatorPolicy.into(),
            VarlinkPinRequestReason::AuthenticatorPolicy
        ));
        assert!(matches!(
            PinRequestReason::FallbackFromUV.into(),
            VarlinkPinRequestReason::FallbackFromUV
        ));
        assert!(matches!(
            PinRequestReason::RelyingPartyRequest.into(),
            VarlinkPinRequestReason::RelyingPartyRequest
        ));
    }

    #[test]
    fn pin_not_set_reasons_map_one_to_one() {
        assert!(matches!(
            PinNotSetReason::PinChangeRequired.into(),
            VarlinkPinNotSetReason::PinChangeRequired
        ));
        assert!(matches!(
            PinNotSetReason::PinNotSet.into(),
            VarlinkPinNotSetReason::PinNotSet
        ));
        assert!(matches!(
            PinNotSetReason::PinPolicyViolation.into(),
            VarlinkPinNotSetReason::PinPolicyViolation
        ));
        assert!(matches!(
            PinNotSetReason::PinTooLong.into(),
            VarlinkPinNotSetReason::PinTooLong
        ));
        assert!(matches!(
            PinNotSetReason::PinTooShort.into(),
            VarlinkPinNotSetReason::PinTooShort
        ));
    }
}
