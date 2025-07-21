use ::btleplug::api::Central;
use futures::StreamExt;
use std::pin::pin;
use tracing::{debug, instrument, trace, warn};
use uuid::Uuid;

use crate::transport::ble::btleplug::{self, FidoDevice};
use crate::transport::cable::crypto::trial_decrypt_advert;
use crate::transport::error::TransportError;

const CABLE_UUID_FIDO: &str = "0000fff9-0000-1000-8000-00805f9b34fb";
const CABLE_UUID_GOOGLE: &str = "0000fde2-0000-1000-8000-00805f9b34fb";

#[derive(Debug)]
pub(crate) struct DecryptedAdvert {
    pub plaintext: [u8; 16],
    pub _nonce: [u8; 10],
    pub routing_id: [u8; 3],
    pub encoded_tunnel_server_domain: u16,
}

impl From<[u8; 16]> for DecryptedAdvert {
    fn from(plaintext: [u8; 16]) -> Self {
        let mut nonce = [0u8; 10];
        nonce.copy_from_slice(&plaintext[1..11]);
        let mut routing_id = [0u8; 3];
        routing_id.copy_from_slice(&plaintext[11..14]);
        let encoded_tunnel_server_domain = u16::from_le_bytes([plaintext[14], plaintext[15]]);
        let mut plaintext_fixed = [0u8; 16];
        plaintext_fixed.copy_from_slice(&plaintext[..16]);
        Self {
            plaintext: plaintext_fixed,
            _nonce: nonce,
            routing_id,
            encoded_tunnel_server_domain,
        }
    }
}

#[instrument(skip_all, err)]
pub(crate) async fn await_advertisement(
    eid_key: &[u8],
) -> Result<(FidoDevice, DecryptedAdvert), TransportError> {
    let uuids = &[
        Uuid::parse_str(CABLE_UUID_FIDO).unwrap(),
        Uuid::parse_str(CABLE_UUID_GOOGLE).unwrap(), // Deprecated, but may still be in use.
    ];
    let stream = btleplug::manager::start_discovery_for_service_data(uuids)
        .await
        .or(Err(TransportError::TransportUnavailable))?;

    let mut stream = pin!(stream);
    while let Some((adapter, peripheral, data)) = stream.as_mut().next().await {
        debug!({ ?peripheral, ?data }, "Found device with service data");

        let Some(device) = btleplug::manager::get_device(peripheral.clone())
            .await
            .or(Err(TransportError::TransportUnavailable))?
        else {
            warn!(
                ?peripheral,
                "Unable to fetch peripheral properties, ignoring"
            );
            continue;
        };

        trace!(?device, ?data, ?eid_key);
        let Some(decrypted) = trial_decrypt_advert(&eid_key, &data) else {
            warn!(?device, "Trial decrypt failed, ignoring");
            continue;
        };
        trace!(?decrypted);

        let advert = DecryptedAdvert::from(decrypted);
        debug!(
            ?device,
            ?decrypted,
            "Successfully decrypted advertisement from device"
        );

        adapter
            .stop_scan()
            .await
            .or(Err(TransportError::TransportUnavailable))?;

        return Ok((device, advert));
    }

    warn!("BLE advertisement discovery stream terminated");
    Err(TransportError::TransportUnavailable)
}
