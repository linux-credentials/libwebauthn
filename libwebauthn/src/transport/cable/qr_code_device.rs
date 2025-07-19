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
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task;
use tracing::instrument;

use super::connection_stages::{
    connection_stage, handshake_stage, proximity_check_stage, ConnectionInput, HandshakeInput,
    MpscUxUpdateSender, ProximityCheckInput, TunnelConnectionInput, UxUpdateSender,
};
use super::known_devices::CableKnownDeviceInfoStore;
use super::tunnel::{self, KNOWN_TUNNEL_DOMAINS};
use super::{channel::CableChannel, channel::ConnectionState, Cable};
use crate::proto::ctap2::cbor;
use crate::transport::cable::digit_encode;
use crate::transport::Device;
use crate::webauthn::error::Error;

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub enum QrCodeOperationHint {
    #[serde(rename = "ga")]
    GetAssertionRequest,
    #[serde(rename = "mc")]
    MakeCredential,
}

#[derive(Debug, Clone, SerializeIndexed)]
pub struct CableQrCode {
    // Key 0: a 33-byte, P-256, X9.62, compressed public key.
    #[serde(index = 0x00)]
    pub public_key: ByteArray<33>,

    // Key 1: a 16-byte random QR secret.
    #[serde(index = 0x01)]
    pub qr_secret: ByteArray<16>,

    /// Key 2: the number of assigned tunnel server domains known to this implementation.
    #[serde(index = 0x02)]
    pub known_tunnel_domains_count: u8,

    /// Key 3: (optional) the current time in epoch seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x03)]
    pub current_time: Option<u64>,

    /// Key 4: (optional) a boolean that is true if the device displaying the QR code can perform state-
    ///   assisted transactions.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x04)]
    pub state_assisted: Option<bool>,

    /// Key 5: either the string “ga” to hint that a getAssertion will follow, or “mc” to hint that a
    ///   makeCredential will follow. Implementations SHOULD treat unknown values as if they were “ga”.
    ///   This ﬁeld exists so that guidance can be given to the user immediately upon scanning the QR code,
    ///   prior to the authenticator receiving any CTAP message. While this hint SHOULD be as accurate as
    ///   possible, it does not constrain the subsequent CTAP messages that the platform may send.
    #[serde(index = 0x05)]
    pub operation_hint: QrCodeOperationHint,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x06)]
    pub supports_non_discoverable_mc: Option<bool>,
}

impl ToString for CableQrCode {
    fn to_string(&self) -> String {
        let serialized = cbor::to_vec(&self).unwrap();
        format!("FIDO:/{}", digit_encode(&serialized))
    }
}

/// Represents a new device which will connect by scanning a QR code.
/// This could be a new device, or an ephmemeral device whose details were not stored.
#[derive(Clone)]
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

    #[instrument(skip_all, err)]
    async fn connection(
        qr_device: &CableQrCodeDevice,
        ux_sender: &MpscUxUpdateSender,
    ) -> Result<super::connection_stages::HandshakeOutput, Error> {
        // Stage 1: Proximity check
        let proximity_input = ProximityCheckInput::new_for_qr_code(qr_device);
        let proximity_output = proximity_check_stage(proximity_input, ux_sender).await?;

        // Stage 2: Connection
        let connection_input = ConnectionInput::new_for_qr_code(qr_device, &proximity_output)?;
        let connection_output = connection_stage(connection_input, ux_sender).await?;

        // Stage 3: Handshake
        let handshake_input =
            HandshakeInput::new_for_qr_code(qr_device, connection_output, proximity_output);
        let handshake_output = handshake_stage(handshake_input, ux_sender).await?;

        Ok(handshake_output)
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
    async fn channel(&'d mut self) -> Result<CableChannel, Error> {
        let (ux_update_sender, _) = broadcast::channel(1);
        let (cbor_tx_send, cbor_tx_recv) = mpsc::channel(16);
        let (cbor_rx_send, cbor_rx_recv) = mpsc::channel(16);
        let (connection_state_sender, connection_state_receiver) =
            watch::channel(ConnectionState::Connecting);

        let ux_update_sender_clone = ux_update_sender.clone();
        let qr_device = self.clone();

        let handle_connection = task::spawn(async move {
            let ux_sender =
                MpscUxUpdateSender::new(ux_update_sender_clone.clone(), connection_state_sender);

            let Ok(handshake_output) = Self::connection(&qr_device, &ux_sender).await else {
                ux_sender.send_error().await;
                return;
            };

            let tunnel_input = TunnelConnectionInput::from_handshake_output(
                handshake_output,
                qr_device.store,
                cbor_tx_recv,
                cbor_rx_send,
            );
            tunnel::connection(tunnel_input).await;

            ux_sender
                .set_connection_state(ConnectionState::Terminated)
                .await;
        });

        Ok(CableChannel {
            handle_connection,
            cbor_sender: cbor_tx_send,
            cbor_receiver: cbor_rx_recv,
            ux_update_sender,
            connection_state_receiver,
        })
    }

    // #[instrument(skip_all)]
    // async fn supported_protocols(&mut self) -> Result<SupportedProtocols, Error> {
    //     Ok(SupportedProtocols::fido2_only())
    // }
}

// TODO: unit tests
// https://source.chromium.org/chromium/chromium/src/+/main:device/fido/cable/v2_handshake_unittest.cc
