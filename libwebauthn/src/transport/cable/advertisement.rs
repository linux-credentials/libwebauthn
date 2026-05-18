use std::collections::BTreeMap;

use ::btleplug::api::Central;
use futures::StreamExt;
use serde_cbor_2 as serde_cbor;
use std::pin::pin;
use tracing::{debug, instrument, trace, warn};
use uuid::Uuid;

use crate::proto::ctap2::cbor::Value;
use crate::transport::ble::btleplug::{self, FidoDevice};
use crate::transport::cable::crypto::trial_decrypt_advert;
use crate::transport::error::TransportError;

const CABLE_UUID_FIDO: &str = "0000fff9-0000-1000-8000-00805f9b34fb";
const CABLE_UUID_GOOGLE: &str = "0000fde2-0000-1000-8000-00805f9b34fb";

/// `transport_channel_identifier` for the BLE data channel.
const TRANSPORT_CHANNEL_BLE: i128 = 1;

/// Parsed CTAP 2.3 hybrid advertisement suffix: a CBOR map of
/// `transport_channel_identifier` -> `channel_extra`.
#[derive(Debug, Clone)]
pub(crate) struct AdvertisementSuffix {
    channels: BTreeMap<i128, Value>,
}

impl AdvertisementSuffix {
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, serde_cbor::Error> {
        let map: BTreeMap<Value, Value> = serde_cbor::from_slice(bytes)?;
        let channels = map
            .into_iter()
            .filter_map(|(k, v)| match k {
                Value::Integer(id) => Some((id, v)),
                _ => None,
            })
            .collect();
        Ok(Self { channels })
    }

    /// L2CAP server PSM for the BLE channel, if advertised and in `u16` range.
    pub fn ble_psm(&self) -> Option<u16> {
        match self.channels.get(&TRANSPORT_CHANNEL_BLE) {
            Some(Value::Integer(psm)) => u16::try_from(*psm).ok(),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct DecryptedAdvert {
    pub plaintext: [u8; 16],
    pub _nonce: [u8; 10],
    pub routing_id: [u8; 3],
    pub encoded_tunnel_server_domain: u16,
    pub suffix: Option<AdvertisementSuffix>,
}

impl From<[u8; 16]> for DecryptedAdvert {
    fn from(plaintext: [u8; 16]) -> Self {
        let [_, n0, n1, n2, n3, n4, n5, n6, n7, n8, n9, r0, r1, r2, d0, d1] = plaintext;
        Self {
            plaintext,
            _nonce: [n0, n1, n2, n3, n4, n5, n6, n7, n8, n9],
            routing_id: [r0, r1, r2],
            encoded_tunnel_server_domain: u16::from_le_bytes([d0, d1]),
            suffix: None,
        }
    }
}

#[instrument(skip_all, err)]
pub(crate) async fn await_advertisement(
    eid_key: &[u8],
) -> Result<(FidoDevice, DecryptedAdvert), TransportError> {
    let uuids = &[
        Uuid::parse_str(CABLE_UUID_FIDO).or(Err(TransportError::InvalidEndpoint))?,
        Uuid::parse_str(CABLE_UUID_GOOGLE).or(Err(TransportError::InvalidEndpoint))?, // Deprecated, but may still be in use.
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
        let Some(decrypted) = trial_decrypt_advert(eid_key, &data) else {
            warn!(?device, "Trial decrypt failed, ignoring");
            continue;
        };
        trace!(?decrypted);

        let mut advert = DecryptedAdvert::from(decrypted);
        if let Some(suffix_bytes) = data.get(20..).filter(|s| !s.is_empty()) {
            match AdvertisementSuffix::from_cbor(suffix_bytes) {
                Ok(suffix) => {
                    trace!(?suffix, "Parsed advertisement suffix");
                    advert.suffix = Some(suffix);
                }
                Err(e) => warn!(
                    ?device,
                    ?e,
                    "Failed to parse advertisement suffix, ignoring it"
                ),
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cbor_map(entries: &[(Value, Value)]) -> Vec<u8> {
        let map: BTreeMap<Value, Value> = entries.iter().cloned().collect();
        serde_cbor::to_vec(&map).unwrap()
    }

    #[test]
    fn suffix_yields_ble_psm() {
        let bytes = cbor_map(&[(Value::Integer(1), Value::Integer(0x1234))]);
        let suffix = AdvertisementSuffix::from_cbor(&bytes).unwrap();
        assert_eq!(suffix.ble_psm(), Some(0x1234));
    }

    #[test]
    fn suffix_ignores_unknown_channel() {
        let bytes = cbor_map(&[(Value::Integer(0), Value::Integer(42))]);
        let suffix = AdvertisementSuffix::from_cbor(&bytes).unwrap();
        assert_eq!(suffix.ble_psm(), None);
    }

    #[test]
    fn suffix_ble_psm_out_of_range_is_none() {
        let bytes = cbor_map(&[(Value::Integer(1), Value::Integer(0x1_0000))]);
        let suffix = AdvertisementSuffix::from_cbor(&bytes).unwrap();
        assert_eq!(suffix.ble_psm(), None);
    }

    #[test]
    fn suffix_ble_psm_wrong_type_is_none() {
        let bytes = cbor_map(&[(Value::Integer(1), Value::Text("nope".into()))]);
        let suffix = AdvertisementSuffix::from_cbor(&bytes).unwrap();
        assert_eq!(suffix.ble_psm(), None);
    }

    #[test]
    fn suffix_empty_map_parses_with_no_psm() {
        let bytes = cbor_map(&[]);
        let suffix = AdvertisementSuffix::from_cbor(&bytes).unwrap();
        assert_eq!(suffix.ble_psm(), None);
    }

    #[test]
    fn suffix_malformed_cbor_errors_without_panic() {
        assert!(AdvertisementSuffix::from_cbor(&[]).is_err());
        assert!(AdvertisementSuffix::from_cbor(&[0xFF, 0x00, 0x13]).is_err());
        // Valid CBOR but not a map.
        assert!(AdvertisementSuffix::from_cbor(&[0x01]).is_err());
    }

    #[test]
    fn decrypted_advert_from_array_has_no_suffix() {
        let advert = DecryptedAdvert::from([0u8; 16]);
        assert!(advert.suffix.is_none());
    }
}
