//! CTAP 2.1 `authenticatorLargeBlobs` command (`0x0C`). Wire-level model only;
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
}

#[cfg_attr(test, derive(SerializeIndexed))]
#[derive(Debug, Default, Clone, DeserializeIndexed)]
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
}
