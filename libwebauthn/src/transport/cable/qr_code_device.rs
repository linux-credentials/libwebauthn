use std::fmt::{Debug, Display};
use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{NonZeroScalar, SecretKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Serialize;
use serde_bytes::ByteArray;
use serde_indexed::SerializeIndexed;
use tokio::sync::mpsc;
use tracing::{debug, error};

use super::known_devices::CableKnownDeviceInfoStore;
use super::tunnel::{self, KNOWN_TUNNEL_DOMAINS};
use super::{channel::CableChannel, Cable};
use crate::proto::ctap2::cbor::CborSerialize;
use crate::transport::cable::advertisement::await_advertisement;
use crate::transport::cable::crypto::{derive, KeyPurpose};
use crate::transport::cable::digit_encode;
use crate::transport::error::Error;
use crate::transport::Device;
use crate::webauthn::TransportError;
use crate::UxUpdate;

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub enum QrCodeOperationHint {
    #[serde(rename = "ga")]
    GetAssertionRequest,
    #[serde(rename = "mc")]
    MakeCredential,
}

#[derive(Debug, SerializeIndexed)]
pub struct CableQrCode {
    // Key 0: a 33-byte, P-256, X9.62, compressed public key.
    pub public_key: ByteArray<33>,
    // Key 1: a 16-byte random QR secret.
    pub qr_secret: ByteArray<16>,
    /// Key 2: the number of assigned tunnel server domains known to this implementation.
    pub known_tunnel_domains_count: u8,
    /// Key 3: (optional) the current time in epoch seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_time: Option<u64>,
    /// Key 4: (optional) a boolean that is true if the device displaying the QR code can perform state-
    ///   assisted transactions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_assisted: Option<bool>,
    /// Key 5: either the string “ga” to hint that a getAssertion will follow, or “mc” to hint that a
    ///   makeCredential will follow. Implementations SHOULD treat unknown values as if they were “ga”.
    ///   This ﬁeld exists so that guidance can be given to the user immediately upon scanning the QR code,
    ///   prior to the authenticator receiving any CTAP message. While this hint SHOULD be as accurate as
    ///   possible, it does not constrain the subsequent CTAP messages that the platform may send.
    pub operation_hint: QrCodeOperationHint,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_non_discoverable_mc: Option<bool>,
}

impl ToString for CableQrCode {
    fn to_string(&self) -> String {
        let serialized = self.to_vec().unwrap();
        format!("FIDO:/{}", digit_encode(&serialized))
    }
}

/// Represents a new device which will connect by scanning a QR code.
/// This could be a new device, or an ephmemeral device whose details were not stored.
pub struct CableQrCodeDevice {
    /// The QR code to be scanned by the new authenticator.
    pub qr_code: CableQrCode,
    /// An ephemeral private key, corresponding to the public key within the QR code.
    pub private_key: NonZeroScalar,
    /// An optional reference to the store. This may be None, if no persistence is desired.
    pub(crate) store: Option<Arc<dyn CableKnownDeviceInfoStore>>,
}

impl Debug for CableQrCodeDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CableQrCodeDevice")
            .field("qr_code", &self.qr_code)
            .field("store", &self.store)
            .finish()
    }
}

impl CableQrCodeDevice {
    /// Generates a QR code, linking the provided known-device store. A device scanning
    /// this QR code may be persisted to the store after a successful connection.
    pub fn new_persistent(
        hint: QrCodeOperationHint,
        store: Arc<dyn CableKnownDeviceInfoStore>,
    ) -> Self {
        Self::new(hint, true, Some(store))
    }

    fn new(
        hint: QrCodeOperationHint,
        state_assisted: bool,
        store: Option<Arc<dyn CableKnownDeviceInfoStore>>,
    ) -> Self {
        let private_key_scalar = NonZeroScalar::random(&mut OsRng);
        let private_key = SecretKey::from_bytes(&private_key_scalar.to_bytes()).unwrap();
        let public_key: [u8; 33] = private_key
            .public_key()
            .as_affine()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        let mut qr_secret = [0u8; 16];
        OsRng::default().fill_bytes(&mut qr_secret);

        let current_unix_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .map(|t| t.as_secs());

        Self {
            qr_code: CableQrCode {
                public_key: ByteArray::from(public_key),
                qr_secret: ByteArray::from(qr_secret),
                known_tunnel_domains_count: KNOWN_TUNNEL_DOMAINS.len() as u8,
                current_time: current_unix_time,
                operation_hint: hint,
                state_assisted: Some(state_assisted),
                supports_non_discoverable_mc: match hint {
                    QrCodeOperationHint::MakeCredential => Some(true),
                    _ => None,
                },
            },
            private_key: private_key_scalar,
            store,
        }
    }
}

impl CableQrCodeDevice {
    /// Generates a QR code, without any known-device store. A device scanning this QR code
    /// will not be persisted.
    pub fn new_transient(hint: QrCodeOperationHint) -> Self {
        Self::new(hint, false, None)
    }
}

unsafe impl Send for CableQrCodeDevice {}

unsafe impl Sync for CableQrCodeDevice {}

impl Display for CableQrCodeDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CableQrCodeDevice")
    }
}

#[async_trait]
impl<'d> Device<'d, Cable, CableChannel> for CableQrCodeDevice {
    async fn channel(&'d mut self) -> Result<(CableChannel, mpsc::Receiver<UxUpdate>), Error> {
        let eid_key: [u8; 64] = derive(self.qr_code.qr_secret.as_ref(), None, KeyPurpose::EIDKey);
        let (_device, advert) = await_advertisement(&eid_key).await?;

        let Some(tunnel_domain) =
            tunnel::decode_tunnel_server_domain(advert.encoded_tunnel_server_domain)
        else {
            error!({ encoded = %advert.encoded_tunnel_server_domain }, "Failed to decode tunnel server domain");
            return Err(Error::Transport(TransportError::InvalidEndpoint));
        };

        debug!(?tunnel_domain, "Creating channel to tunnel server");
        let routing_id_str = hex::encode(&advert.routing_id);
        let _nonce_str = hex::encode(&advert.nonce);

        let tunnel_id = &derive(self.qr_code.qr_secret.as_ref(), None, KeyPurpose::TunnelID)[..16];
        let tunnel_id_str = hex::encode(&tunnel_id);

        let mut psk: [u8; 32] = [0u8; 32];
        psk.copy_from_slice(
            &derive(
                self.qr_code.qr_secret.as_ref(),
                Some(&advert.plaintext),
                KeyPurpose::PSK,
            )[..32],
        );

        let connection_type = tunnel::CableTunnelConnectionType::QrCode {
            routing_id: routing_id_str,
            tunnel_id: tunnel_id_str.clone(),
            private_key: self.private_key,
        };
        let mut ws_stream = tunnel::connect(&tunnel_domain, &connection_type).await?;
        let noise_state = tunnel::do_handshake(&mut ws_stream, psk, &connection_type).await?;
        tunnel::channel(
            &connection_type,
            noise_state,
            &tunnel_domain,
            &self.store,
            ws_stream,
        )
        .await
    }

    // #[instrument(skip_all)]
    // async fn supported_protocols(&mut self) -> Result<SupportedProtocols, Error> {
    //     Ok(SupportedProtocols::fido2_only())
    // }
}

// TODO: unit tests
// https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake_unittest.cc
