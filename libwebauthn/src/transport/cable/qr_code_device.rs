use std::fmt::{Debug, Display};
use std::pin::pin;
use std::time::SystemTime;

use async_trait::async_trait;
use futures::StreamExt;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{NonZeroScalar, SecretKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Serialize;
use serde_bytes::ByteArray;
use serde_indexed::SerializeIndexed;
use tokio::sync::mpsc;
use tracing::{debug, error, trace, warn};
use uuid::Uuid;

use super::known_devices::CableKnownDeviceInfoStore;
use super::tunnel::{self, KNOWN_TUNNEL_DOMAINS};
use super::{channel::CableChannel, Cable};
use crate::transport::ble::btleplug::{self, FidoDevice};
use crate::transport::cable::crypto::{derive, trial_decrypt_advert, KeyPurpose};
use crate::transport::cable::digit_encode;
use crate::transport::error::Error;
use crate::transport::Device;
use crate::webauthn::TransportError;
use crate::UxUpdate;

const CABLE_UUID_FIDO: &str = "0000fff9-0000-1000-8000-00805f9b34fb";
const CABLE_UUID_GOOGLE: &str = "0000fde2-0000-1000-8000-00805f9b34fb";

#[derive(Debug, Clone, Copy)]
pub enum QrCodeOperationHint {
    GetAssertionRequest,
    MakeCredential,
}

impl Serialize for QrCodeOperationHint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            QrCodeOperationHint::GetAssertionRequest => serializer.serialize_str("ga"),
            QrCodeOperationHint::MakeCredential => serializer.serialize_str("mc"),
        }
    }
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
        let serialized = serde_cbor::to_vec(self).unwrap();
        format!("FIDO:/{}", digit_encode(&serialized))
    }
}

/// Represents a new device which will connect by scanning a QR code.
/// This could be a new device, or an ephmemeral device whose details were not stored.
pub struct CableQrCodeDevice<'d> {
    /// The QR code to be scanned by the new authenticator.
    pub qr_code: CableQrCode,
    /// An ephemeral private, corresponding to the public key within the QR code.
    pub private_key: NonZeroScalar,
    /// An optional reference to the store. This may be None, if no persistence is desired.
    store: Option<&'d mut Box<dyn CableKnownDeviceInfoStore>>,
}

impl Debug for CableQrCodeDevice<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CableQrCodeDevice")
            .field("qr_code", &self.qr_code)
            .field("store", &self.store)
            .finish()
    }
}

#[derive(Debug)]
struct DecryptedAdvert {
    plaintext: [u8; 16],
    nonce: [u8; 10],
    routing_id: [u8; 3],
    encoded_tunnel_server_domain: u16,
}

impl From<&[u8]> for DecryptedAdvert {
    fn from(plaintext: &[u8]) -> Self {
        let mut nonce = [0u8; 10];
        nonce.copy_from_slice(&plaintext[1..11]);
        let mut routing_id = [0u8; 3];
        routing_id.copy_from_slice(&plaintext[11..14]);
        let encoded_tunnel_server_domain = u16::from_le_bytes([plaintext[14], plaintext[15]]);
        let mut plaintext_fixed = [0u8; 16];
        plaintext_fixed.copy_from_slice(&plaintext[..16]);
        Self {
            plaintext: plaintext_fixed,
            nonce,
            routing_id,
            encoded_tunnel_server_domain,
        }
    }
}

impl<'d> CableQrCodeDevice<'d> {
    /// Generates a QR code, linking the provided known-device store. A device scanning
    /// this QR code may be persisted to the store after a successful connection.
    pub fn new_persistent(
        hint: QrCodeOperationHint,
        store: &'d mut Box<dyn CableKnownDeviceInfoStore>,
    ) -> Self {
        Self::new(hint, true, Some(store))
    }

    fn new(
        hint: QrCodeOperationHint,
        state_assisted: bool,
        store: Option<&'d mut Box<dyn CableKnownDeviceInfoStore>>,
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

impl CableQrCodeDevice<'_> {
    /// Generates a QR code, without any known-device store. A device scanning this QR code
    /// will not be persisted.
    pub fn new_transient(hint: QrCodeOperationHint) -> Self {
        Self::new(hint, false, None)
    }

    async fn await_advertisement(&self) -> Result<(FidoDevice, DecryptedAdvert), Error> {
        let stream = btleplug::manager::start_discovery_for_service_data(vec![
            Uuid::parse_str(CABLE_UUID_GOOGLE).unwrap(),
            Uuid::parse_str(CABLE_UUID_FIDO).unwrap(),
        ])
        .await
        .or(Err(Error::Transport(TransportError::TransportUnavailable)))?;

        let mut stream = pin!(stream);
        while let Some((peripheral, data)) = stream.as_mut().next().await {
            debug!({ ?peripheral, ?data }, "Found device with service data");

            let Some(device) = btleplug::manager::get_device(peripheral.clone())
                .await
                .or(Err(Error::Transport(TransportError::TransportUnavailable)))?
            else {
                warn!(
                    ?peripheral,
                    "Unable to fetch peripheral properties, ignoring"
                );
                continue;
            };

            let eid_key: Vec<u8> = derive(&self.qr_code.qr_secret, None, KeyPurpose::EIDKey);
            trace!(?device, ?data, ?eid_key);

            let Some(decrypted) = trial_decrypt_advert(&eid_key, &data) else {
                warn!(?device, "Trial decrypt failed, ignoring");
                continue;
            };
            trace!(?decrypted);

            let advert = DecryptedAdvert::from(decrypted.as_slice());
            debug!(
                ?device,
                ?decrypted,
                "Successfully decrypted advertisement from device"
            );

            return Ok((device, advert));
        }

        unreachable!()
    }
}

unsafe impl Send for CableQrCodeDevice<'_> {}

unsafe impl Sync for CableQrCodeDevice<'_> {}

impl Display for CableQrCodeDevice<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CableQrCodeDevice")
    }
}

#[async_trait]
impl<'d> Device<'d, Cable, CableChannel<'d>> for CableQrCodeDevice<'_> {
    async fn channel(&'d mut self) -> Result<(CableChannel<'d>, mpsc::Receiver<UxUpdate>), Error> {
        let (_device, advert) = self.await_advertisement().await?;

        let Some(tunnel_domain) =
            tunnel::decode_tunnel_server_domain(advert.encoded_tunnel_server_domain)
        else {
            error!({ encoded = %advert.encoded_tunnel_server_domain }, "Failed to decode tunnel server domain");
            return Err(Error::Transport(TransportError::InvalidEndpoint));
        };

        debug!(?tunnel_domain, "Creating channel to tunnel server");
        let routing_id_str = hex::encode(&advert.routing_id);
        let _nonce_str = hex::encode(&advert.nonce);

        let tunnel_id = &derive(&self.qr_code.qr_secret.as_ref(), None, KeyPurpose::TunnelID)[..16];
        let tunnel_id_str = hex::encode(&tunnel_id);

        let psk: &[u8; 32] = &derive(
            &self.qr_code.qr_secret.as_ref(),
            Some(&advert.plaintext),
            KeyPurpose::PSK,
        )[..32]
            .try_into()
            .unwrap();

        return tunnel::connect(
            self,
            &tunnel_domain,
            &routing_id_str,
            &tunnel_id_str,
            psk,
            &self.private_key,
        )
        .await;
    }

    // #[instrument(skip_all)]
    // async fn supported_protocols(&mut self) -> Result<SupportedProtocols, Error> {
    //     Ok(SupportedProtocols::fido2_only())
    // }
}

// TODO: unit tests
// https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake_unittest.cc
