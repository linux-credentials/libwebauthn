//! Relying party hints about how the user is expected to authenticate.
//!
//! WebAuthn Level 3 lets a site express a preference through three signals: the hints array,
//! per-credential transports, and, on registration, the authenticator attachment. This module
//! parses them and merges them into a single ordered list of transports, so that a device chooser
//! can offer the likely ones first.
//!
//! See <https://www.w3.org/TR/webauthn-3/#enum-hints>.

use serde::Deserialize;

use super::{GetAssertionRequest, MakeCredentialRequest};
use crate::proto::ctap2::Ctap2Transport;

/// A relying party's hint about how the user is expected to authenticate.
///
/// A value we do not recognise parses as [`Unknown`](Self::Unknown) rather than failing, and is
/// ignored when merging.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum PublicKeyCredentialHint {
    /// A physical, roaming security key.
    SecurityKey,
    /// A platform authenticator built into the client device.
    ClientDevice,
    /// A general purpose authenticator, such as a phone reached over hybrid transport.
    Hybrid,
    /// A value we do not recognise.
    #[serde(other)]
    Unknown,
}

impl PublicKeyCredentialHint {
    /// Parses a hint held as a raw string, for callers that bypass the JSON layer.
    pub fn from_dom_string(s: &str) -> Self {
        match s {
            "security-key" => Self::SecurityKey,
            "client-device" => Self::ClientDevice,
            "hybrid" => Self::Hybrid,
            _ => Self::Unknown,
        }
    }
}

/// The authenticator attachment requested at registration. Assertion requests carry no attachment.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum AuthenticatorAttachment {
    /// An authenticator built into the client device.
    Platform,
    /// A roaming authenticator.
    CrossPlatform,
    /// A value we do not recognise.
    #[serde(other)]
    Unknown,
}

impl AuthenticatorAttachment {
    /// Parses an attachment held as a raw string, for callers that bypass the JSON layer.
    pub fn from_dom_string(s: &str) -> Self {
        match s {
            "platform" => Self::Platform,
            "cross-platform" => Self::CrossPlatform,
            _ => Self::Unknown,
        }
    }
}

/// Appends the transports that are not already present, keeping the first occurrence. The lists are
/// only ever a handful of entries, so a linear scan is fine.
fn push_absent(out: &mut Vec<Ctap2Transport>, ts: &[Ctap2Transport]) {
    for t in ts {
        if !out.contains(t) {
            out.push(t.clone());
        }
    }
}

/// Merges a relying party's signals into one transport preference, most preferred first.
///
/// Hints outrank the attachment, which outranks per-credential transports. The spec allows the
/// three to contradict each other and gives hints the final say, so precedence falls out of the
/// order in which each source contributes.
///
/// The result is advisory ordering, never an eligibility filter, and it is partial: a transport the
/// site did not mention is simply absent, and a caller should rank it last rather than exclude it.
/// Empty input means no preference.
fn merge_transport_preference(
    hints: &[PublicKeyCredentialHint],
    attachment: Option<AuthenticatorAttachment>,
    descriptor_transports: &[Ctap2Transport],
) -> Vec<Ctap2Transport> {
    use AuthenticatorAttachment as A;
    use Ctap2Transport::*;
    use PublicKeyCredentialHint as H;

    let mut out: Vec<Ctap2Transport> = Vec::new();

    // Hints rank highest, and the array is already in descending preference order. The order within
    // a bucket is our own choice, as the spec does not rank them.
    for h in hints {
        match h {
            H::SecurityKey => push_absent(&mut out, &[Usb, Nfc, Ble, SmartCard]),
            H::ClientDevice => push_absent(&mut out, &[Internal]),
            H::Hybrid => push_absent(&mut out, &[Hybrid]),
            H::Unknown => {}
        }
    }

    // The attachment only fills gaps. It never reorders anything a hint already placed.
    match attachment {
        Some(A::Platform) => push_absent(&mut out, &[Internal]),
        Some(A::CrossPlatform) => push_absent(&mut out, &[Usb, Nfc, Ble, SmartCard, Hybrid]),
        Some(A::Unknown) | None => {}
    }

    // Per-credential transports fill the remaining gaps. Values we do not recognise are ignored.
    for t in descriptor_transports {
        if !matches!(t, Ctap2Transport::Other(_)) && !out.contains(t) {
            out.push(t.clone());
        }
    }

    // A hybrid hint without a client-device hint is a signal not to promote the platform
    // authenticator, so drop it even if the attachment or a credential transport put it back.
    if hints.contains(&H::Hybrid) && !hints.contains(&H::ClientDevice) {
        out.retain(|t| *t != Internal);
    }

    out
}

/// A request that carries relying party hints about the preferred transport.
pub trait TransportHintedRequest {
    /// The advisory transport preference for this request, most preferred first.
    ///
    /// This is ordering only, and it is partial. A device whose transport is absent must still be
    /// offered, just ranked last. It does not apply attachment eligibility, so a caller that needs
    /// to exclude ineligible modalities should read the attachment field on the request itself.
    fn preferred_transports(&self) -> Vec<Ctap2Transport>;
}

impl TransportHintedRequest for GetAssertionRequest {
    fn preferred_transports(&self) -> Vec<Ctap2Transport> {
        // The allow list is already in descending preference order. A descriptor with no transports,
        // which is how a discoverable credential arrives, contributes nothing.
        let descriptor_transports: Vec<Ctap2Transport> = self
            .allow
            .iter()
            .flat_map(|d| d.transports.iter().flatten().cloned())
            .collect();
        merge_transport_preference(&self.hints, None, &descriptor_transports)
    }
}

impl TransportHintedRequest for MakeCredentialRequest {
    fn preferred_transports(&self) -> Vec<Ctap2Transport> {
        // The exclude list is a signal to avoid, not a preference, so it contributes nothing here.
        merge_transport_preference(&self.hints, self.authenticator_attachment, &[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use AuthenticatorAttachment as A;
    use Ctap2Transport::*;
    use PublicKeyCredentialHint as H;

    // --- merge: coarse -> fine mapping -------------------------------------------------------

    #[test]
    fn security_key_expands_to_roaming_set() {
        assert_eq!(
            merge_transport_preference(&[H::SecurityKey], None, &[]),
            vec![Usb, Nfc, Ble, SmartCard]
        );
    }

    #[test]
    fn client_device_expands_to_internal() {
        assert_eq!(
            merge_transport_preference(&[H::ClientDevice], None, &[]),
            vec![Internal]
        );
    }

    #[test]
    fn hybrid_expands_to_hybrid() {
        assert_eq!(
            merge_transport_preference(&[H::Hybrid], None, &[]),
            vec![Hybrid]
        );
    }

    #[test]
    fn platform_attachment_adds_internal() {
        assert_eq!(
            merge_transport_preference(&[], Some(A::Platform), &[]),
            vec![Internal]
        );
    }

    #[test]
    fn cross_platform_attachment_adds_roaming_set() {
        assert_eq!(
            merge_transport_preference(&[], Some(A::CrossPlatform), &[]),
            vec![Usb, Nfc, Ble, SmartCard, Hybrid]
        );
    }

    // --- merge: ordering & precedence --------------------------------------------------------

    #[test]
    fn hint_array_order_is_descending_preference() {
        assert_eq!(
            merge_transport_preference(&[H::Hybrid, H::SecurityKey], None, &[]),
            vec![Hybrid, Usb, Nfc, Ble, SmartCard]
        );
    }

    #[test]
    fn first_contradictory_hint_wins() {
        // client-device before security-key => Internal ranks first.
        assert_eq!(
            merge_transport_preference(&[H::ClientDevice, H::SecurityKey], None, &[]),
            vec![Internal, Usb, Nfc, Ble, SmartCard]
        );
    }

    #[test]
    fn hints_outrank_attachment() {
        // create: client-device hint + cross-platform attachment => the hint's Internal ranks
        // first, then the attachment gap-fills the roaming transports.
        assert_eq!(
            merge_transport_preference(&[H::ClientDevice], Some(A::CrossPlatform), &[]),
            vec![Internal, Usb, Nfc, Ble, SmartCard, Hybrid]
        );
    }

    #[test]
    fn all_three_sources_respect_precedence() {
        // All three inputs populated: client-device hint contributes Internal first; the platform
        // attachment re-adds nothing; the descriptor's Usb gap-fills last.
        assert_eq!(
            merge_transport_preference(&[H::ClientDevice], Some(A::Platform), &[Usb]),
            vec![Internal, Usb]
        );
    }

    // --- merge: de-duplication ---------------------------------------------------------------

    #[test]
    fn cross_source_duplicates_are_removed_keeping_first() {
        // security-key hint already yields Usb; a descriptor Usb must not double it.
        assert_eq!(
            merge_transport_preference(&[H::SecurityKey], None, &[Usb]),
            vec![Usb, Nfc, Ble, SmartCard]
        );
    }

    #[test]
    fn descriptor_transports_gap_fill_in_order() {
        assert_eq!(
            merge_transport_preference(&[], None, &[Nfc, Usb, Nfc]),
            vec![Nfc, Usb]
        );
    }

    #[test]
    fn unknown_descriptor_transport_is_skipped() {
        // A forward-compatible RP may list a transport libwebauthn does not model; it must be
        // ignored, not surfaced as a preference.
        assert_eq!(
            merge_transport_preference(&[], None, &[Other("future-transport".to_owned()), Usb]),
            vec![Usb]
        );
    }

    // --- merge: unknown / empty --------------------------------------------------------------

    #[test]
    fn unknown_hint_is_skipped() {
        assert_eq!(
            merge_transport_preference(&[H::SecurityKey, H::Unknown], None, &[]),
            vec![Usb, Nfc, Ble, SmartCard]
        );
    }

    #[test]
    fn unknown_hint_alone_contributes_nothing() {
        assert_eq!(
            merge_transport_preference(&[H::Unknown], None, &[]),
            Vec::<Ctap2Transport>::new()
        );
    }

    #[test]
    fn empty_input_yields_empty() {
        assert_eq!(
            merge_transport_preference(&[], None, &[]),
            Vec::<Ctap2Transport>::new()
        );
    }

    #[test]
    fn unknown_attachment_contributes_nothing() {
        assert_eq!(
            merge_transport_preference(&[], Some(A::Unknown), &[]),
            Vec::<Ctap2Transport>::new()
        );
    }

    // --- merge: hybrid negative signal -------------------------------------------------------

    #[test]
    fn hybrid_suppresses_platform_from_attachment() {
        assert_eq!(
            merge_transport_preference(&[H::Hybrid], Some(A::Platform), &[]),
            vec![Hybrid]
        );
    }

    #[test]
    fn hybrid_suppresses_platform_from_descriptor() {
        assert_eq!(
            merge_transport_preference(&[H::Hybrid], None, &[Internal]),
            vec![Hybrid]
        );
    }

    #[test]
    fn hybrid_and_client_device_together_keep_internal() {
        assert_eq!(
            merge_transport_preference(&[H::Hybrid, H::ClientDevice], None, &[]),
            vec![Hybrid, Internal]
        );
    }

    // --- enum deserialization ----------------------------------------------------------------

    #[test]
    fn hint_deserializes_by_string_value() {
        assert_eq!(
            serde_json::from_str::<PublicKeyCredentialHint>("\"security-key\"").unwrap(),
            H::SecurityKey
        );
        assert_eq!(
            serde_json::from_str::<PublicKeyCredentialHint>("\"nonsense\"").unwrap(),
            H::Unknown
        );
    }

    #[test]
    fn attachment_deserializes_by_string_value() {
        assert_eq!(
            serde_json::from_str::<AuthenticatorAttachment>("\"cross-platform\"").unwrap(),
            A::CrossPlatform
        );
        assert_eq!(
            serde_json::from_str::<AuthenticatorAttachment>("\"nonsense\"").unwrap(),
            A::Unknown
        );
    }

    #[test]
    fn unknown_element_does_not_fail_the_array() {
        assert_eq!(
            serde_json::from_str::<Vec<PublicKeyCredentialHint>>(
                "[\"security-key\",\"totally-unknown\"]"
            )
            .unwrap(),
            vec![H::SecurityKey, H::Unknown]
        );
    }

    #[test]
    fn from_dom_string_matches_serde() {
        for (s, h) in [
            ("security-key", H::SecurityKey),
            ("client-device", H::ClientDevice),
            ("hybrid", H::Hybrid),
            ("whatever", H::Unknown),
        ] {
            assert_eq!(PublicKeyCredentialHint::from_dom_string(s), h);
        }
        for (s, a) in [
            ("platform", A::Platform),
            ("cross-platform", A::CrossPlatform),
            ("whatever", A::Unknown),
        ] {
            assert_eq!(AuthenticatorAttachment::from_dom_string(s), a);
        }
    }
}
