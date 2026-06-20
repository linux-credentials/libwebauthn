//! CTAP 2.2 `authenticatorLargeBlobs` command (`0x0C`). Wire-level model only;
//! see [`crate::ops::webauthn::large_blob`] for the high-level read pipeline.

use serde_bytes::ByteBuf;
use serde_indexed::{DeserializeIndexed, SerializeIndexed};

/// Request parameters. `get` (read) and `set` (write) are mutually exclusive.
#[derive(Debug, Clone, SerializeIndexed)]
pub struct Ctap2LargeBlobsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x01)]
    pub get: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x02)]
    pub set: Option<ByteBuf>,

    #[serde(index = 0x03)]
    pub offset: u32,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x04)]
    pub length: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x05)]
    pub pin_uv_auth_param: Option<ByteBuf>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x06)]
    pub pin_uv_auth_protocol: Option<u32>,
}

impl Ctap2LargeBlobsRequest {
    pub fn new_get(offset: u32, length: u32) -> Self {
        Self {
            get: Some(length),
            set: None,
            offset,
            length: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        }
    }

    /// First chunk of a chunked write. CTAP 2.2 §6.10.2 requires `length` only when `offset == 0`.
    /// Pass `None` for `pin_uv_auth` on unprotected authenticators (no clientPin, no built-in UV).
    pub fn new_set_first(
        chunk: Vec<u8>,
        total_length: u32,
        pin_uv_auth: Option<(Vec<u8>, u32)>,
    ) -> Self {
        let (pin_uv_auth_param, pin_uv_auth_protocol) = match pin_uv_auth {
            Some((p, v)) => (Some(ByteBuf::from(p)), Some(v)),
            None => (None, None),
        };
        Self {
            get: None,
            set: Some(ByteBuf::from(chunk)),
            offset: 0,
            length: Some(total_length),
            pin_uv_auth_param,
            pin_uv_auth_protocol,
        }
    }

    /// Continuation chunk. CTAP 2.2 §6.10.2 forbids `length` when `offset != 0`.
    /// Pass `None` for `pin_uv_auth` on unprotected authenticators.
    pub fn new_set_continuation(
        chunk: Vec<u8>,
        offset: u32,
        pin_uv_auth: Option<(Vec<u8>, u32)>,
    ) -> Self {
        let (pin_uv_auth_param, pin_uv_auth_protocol) = match pin_uv_auth {
            Some((p, v)) => (Some(ByteBuf::from(p)), Some(v)),
            None => (None, None),
        };
        Self {
            get: None,
            set: Some(ByteBuf::from(chunk)),
            offset,
            length: None,
            pin_uv_auth_param,
            pin_uv_auth_protocol,
        }
    }
}

#[cfg_attr(test, derive(SerializeIndexed))]
#[derive(Debug, Default, Clone, DeserializeIndexed)]
#[non_exhaustive]
pub struct Ctap2LargeBlobsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x01)]
    pub config: Option<ByteBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::ctap2::cbor;

    #[test]
    fn get_request_round_trips_through_cbor() {
        let req = Ctap2LargeBlobsRequest::new_get(0, 1024);
        let bytes = cbor::to_vec(&req).expect("serialize");
        assert_eq!(bytes[0], 0xa2, "expected CBOR map of two items");
        let value: cbor::Value = cbor::from_slice(&bytes).expect("deserialize");
        let cbor::Value::Map(map) = value else {
            panic!("expected map");
        };
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn set_first_encodes_length_and_offset_zero() {
        let req =
            Ctap2LargeBlobsRequest::new_set_first(vec![0x01, 0x02], 17, Some((vec![0xAA; 16], 2)));
        let bytes = cbor::to_vec(&req).expect("serialize");
        let value: cbor::Value = cbor::from_slice(&bytes).expect("deserialize");
        let cbor::Value::Map(map) = value else {
            panic!("expected map");
        };
        let pairs: std::collections::BTreeMap<_, _> = map
            .into_iter()
            .filter_map(|(k, v)| match k {
                cbor::Value::Integer(i) => Some((i, v)),
                _ => None,
            })
            .collect();
        assert!(matches!(pairs.get(&0x02), Some(cbor::Value::Bytes(_))));
        assert_eq!(pairs.get(&0x03), Some(&cbor::Value::Integer(0)));
        assert_eq!(pairs.get(&0x04), Some(&cbor::Value::Integer(17)));
        assert!(matches!(pairs.get(&0x05), Some(cbor::Value::Bytes(_))));
        assert_eq!(pairs.get(&0x06), Some(&cbor::Value::Integer(2)));
        assert!(!pairs.contains_key(&0x01), "get must not be present");
    }

    #[test]
    fn set_continuation_omits_length() {
        let req =
            Ctap2LargeBlobsRequest::new_set_continuation(vec![0xFF], 64, Some((vec![0xBB; 16], 2)));
        let bytes = cbor::to_vec(&req).expect("serialize");
        let value: cbor::Value = cbor::from_slice(&bytes).expect("deserialize");
        let cbor::Value::Map(map) = value else {
            panic!("expected map");
        };
        let pairs: std::collections::BTreeMap<_, _> = map
            .into_iter()
            .filter_map(|(k, v)| match k {
                cbor::Value::Integer(i) => Some((i, v)),
                _ => None,
            })
            .collect();
        assert_eq!(pairs.get(&0x03), Some(&cbor::Value::Integer(64)));
        assert!(!pairs.contains_key(&0x04), "length must be absent");
        assert!(matches!(pairs.get(&0x02), Some(cbor::Value::Bytes(_))));
    }

    #[test]
    fn set_first_unauthenticated_omits_auth_params() {
        // CTAP 2.2 §6.10.2: unprotected authenticators skip the pinUvAuth verification block,
        // so the platform omits both pinUvAuthParam and pinUvAuthProtocol.
        let req = Ctap2LargeBlobsRequest::new_set_first(vec![0x01, 0x02], 17, None);
        let bytes = cbor::to_vec(&req).expect("serialize");
        let value: cbor::Value = cbor::from_slice(&bytes).expect("deserialize");
        let cbor::Value::Map(map) = value else {
            panic!("expected map");
        };
        let pairs: std::collections::BTreeMap<_, _> = map
            .into_iter()
            .filter_map(|(k, v)| match k {
                cbor::Value::Integer(i) => Some((i, v)),
                _ => None,
            })
            .collect();
        assert!(!pairs.contains_key(&0x05));
        assert!(!pairs.contains_key(&0x06));
    }
}
