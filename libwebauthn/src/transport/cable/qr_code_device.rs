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
use serde_repr::Serialize_repr;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task;
use tracing::instrument;

use super::connection_stages::{
    connection_stage, handshake_stage, proximity_check_stage, ConnectionInput, HandshakeInput,
    MpscUxUpdateSender, ProximityCheckInput, TunnelConnectionInput, UxUpdateSender,
};
use super::known_devices::CableKnownDeviceInfoStore;
use super::protocol;
use super::tunnel::KNOWN_TUNNEL_DOMAINS;
use super::{channel::CableChannel, channel::ConnectionState, Cable};
use crate::proto::ctap2::cbor;
use crate::transport::cable::digit_encode;
use crate::transport::Device;
use crate::webauthn::error::Error;
use crate::webauthn::TransportError;

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub enum QrCodeOperationHint {
    #[serde(rename = "ga")]
    GetAssertionRequest,
    #[serde(rename = "mc")]
    MakeCredential,
}

/// One of the data transfer channels listed in QR code key 6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr)]
#[repr(u8)]
pub(crate) enum CableTransportChannel {
    WebSocket = 0,
    Ble = 1,
}

/// Which hybrid transport(s) the QR code advertises support for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CableTransports {
    /// caBLE v2 only: advertise the cloud-assisted WebSocket tunnel. Omits QR
    /// key 6, so the QR stays valid for legacy peers that read key 6 as a
    /// `supports_non_discoverable_mc` boolean and would hard-reject a CBOR
    /// array (e.g. Google Play services Fido pre-CTAP-2.3).
    CloudAssistedOnly,

    /// caBLE v2 + CTAP 2.3 hybrid: advertise both the cloud-assisted WebSocket
    /// tunnel and the direct BLE L2CAP data channel via QR key 6. CTAP 2.3-
    /// aware peers may open the L2CAP channel; older peers silently ignore
    /// key 6 and fall back to the WebSocket tunnel.
    CloudAssistedOrLocal,
}

impl CableTransports {
    /// CBOR form of QR key 6. `None` for `CloudAssistedOnly` so a legacy peer
    /// doesn't see an unexpected CBOR array where it wants a boolean.
    pub(crate) fn to_qr_field(self) -> Option<Vec<CableTransportChannel>> {
        match self {
            Self::CloudAssistedOnly => None,
            Self::CloudAssistedOrLocal => Some(vec![
                CableTransportChannel::WebSocket,
                CableTransportChannel::Ble,
            ]),
        }
    }
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

    /// Key 6: data transfer channels the client supports (CTAP 2.3 hybrid).
    /// Set via [`CableTransports`] at construction time; stored here as a
    /// `Vec` for CBOR serialization. `None` omits key 6 entirely so the QR
    /// stays valid for caBLE v2 peers that interpret key 6 incompatibly.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x06)]
    pub(crate) transports: Option<Vec<CableTransportChannel>>,
}

impl std::fmt::Display for CableQrCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let serialized = cbor::to_vec(&self).map_err(|_| std::fmt::Error)?;
        write!(f, "FIDO:/{}", digit_encode(&serialized))
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
        transports: CableTransports,
    ) -> Result<Self, Error> {
        Self::new(hint, true, Some(store), transports)
    }

    fn new(
        hint: QrCodeOperationHint,
        state_assisted: bool,
        store: Option<Arc<dyn CableKnownDeviceInfoStore>>,
        transports: CableTransports,
    ) -> Result<Self, Error> {
        let private_key_scalar = NonZeroScalar::random(&mut OsRng);
        let private_key = SecretKey::from(private_key_scalar);
        let public_key: [u8; 33] = private_key
            .public_key()
            .as_affine()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .map_err(|_| Error::Transport(TransportError::InvalidKey))?;
        let mut qr_secret = [0u8; 16];
        OsRng.fill_bytes(&mut qr_secret);

        let current_unix_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .map(|t| t.as_secs());

        let transports = transports.to_qr_field();

        Ok(Self {
            qr_code: CableQrCode {
                public_key: ByteArray::from(public_key),
                qr_secret: ByteArray::from(qr_secret),
                known_tunnel_domains_count: KNOWN_TUNNEL_DOMAINS.len() as u8,
                current_time: current_unix_time,
                operation_hint: hint,
                // Chrome convention: omit key 4 when false (presence implies
                // caBLE v2.1, absence implies v2.0).
                state_assisted: state_assisted.then_some(true),
                transports,
            },
            private_key: private_key_scalar,
            store,
        })
    }
}

impl CableQrCodeDevice {
    /// Generates a QR code, without any known-device store. A device scanning this QR code
    /// will not be persisted.
    pub fn new_transient(
        hint: QrCodeOperationHint,
        transports: CableTransports,
    ) -> Result<Self, Error> {
        Self::new(hint, false, None, transports)
    }

    #[instrument(skip_all, err)]
    async fn connection(
        qr_device: &CableQrCodeDevice,
        ux_sender: &MpscUxUpdateSender,
    ) -> Result<super::connection_stages::HandshakeOutput, Error> {
        // Stage 1: Proximity check
        let proximity_input = ProximityCheckInput::new_for_qr_code(qr_device)?;
        let proximity_output = proximity_check_stage(proximity_input, ux_sender).await?;

        // Stage 2: Connection
        let connection_input = ConnectionInput::new_for_qr_code(qr_device, &proximity_output)?;
        let connection_output = connection_stage(connection_input, ux_sender).await?;

        // Stage 3: Handshake
        let handshake_input =
            HandshakeInput::new_for_qr_code(qr_device, connection_output, proximity_output)?;
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
        let (ux_update_sender, _) = broadcast::channel(16);
        let (cbor_tx_send, cbor_tx_recv) = mpsc::channel(16);
        let (cbor_rx_send, cbor_rx_recv) = mpsc::channel(16);
        let (connection_state_sender, connection_state_receiver) =
            watch::channel(ConnectionState::Connecting);

        let ux_update_sender_clone = ux_update_sender.clone();
        let qr_device = self.clone();

        let handle_connection = task::spawn(async move {
            let ux_sender =
                MpscUxUpdateSender::new(ux_update_sender_clone.clone(), connection_state_sender);

            let handshake_output = match Self::connection(&qr_device, &ux_sender).await {
                Ok(handshake_output) => handshake_output,
                Err(e) => {
                    let transport_err = match e {
                        Error::Transport(t) => t,
                        _ => TransportError::ConnectionFailed,
                    };
                    ux_sender.send_error(transport_err).await;
                    return;
                }
            };

            let tunnel_input = TunnelConnectionInput::from_handshake_output(
                handshake_output,
                qr_device.store,
                cbor_tx_recv,
                cbor_rx_send,
            );
            protocol::connection(tunnel_input).await;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn qr_code_omits_key_6_for_cloud_assisted_only() {
        let device = CableQrCodeDevice::new_transient(
            QrCodeOperationHint::MakeCredential,
            CableTransports::CloudAssistedOnly,
        )
        .unwrap();
        let bytes = cbor::to_vec(&device.qr_code).unwrap();
        let map: BTreeMap<u64, cbor::Value> = cbor::from_slice(&bytes).unwrap();
        assert_eq!(map.get(&6), None);
    }

    #[test]
    fn qr_code_encodes_key_6_for_cloud_assisted_or_local() {
        let device = CableQrCodeDevice::new_transient(
            QrCodeOperationHint::MakeCredential,
            CableTransports::CloudAssistedOrLocal,
        )
        .unwrap();
        let bytes = cbor::to_vec(&device.qr_code).unwrap();
        let map: BTreeMap<u64, cbor::Value> = cbor::from_slice(&bytes).unwrap();
        assert_eq!(
            map.get(&6),
            Some(&cbor::Value::Array(vec![
                cbor::Value::Integer(0),
                cbor::Value::Integer(1),
            ])),
        );
    }
}
