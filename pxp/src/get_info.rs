//! The getInfo response carried in the post-handshake message. Only the
//! members CTAP requires are decoded; the CTAP layer decodes the rest.
use serde_bytes::ByteBuf;
use serde_indexed::DeserializeIndexed;

#[derive(Debug, Clone, DeserializeIndexed)]
#[allow(dead_code)]
pub(crate) struct GetInfoResponse {
    /// versions (0x01)
    #[serde(index = 0x01)]
    pub versions: Vec<String>,

    /// aaguid (0x03)
    #[serde(index = 0x03)]
    pub aaguid: ByteBuf,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::cbor::{self, Value};

    fn get_info(entries: Vec<(i128, Value)>) -> Vec<u8> {
        let map: BTreeMap<Value, Value> = entries
            .into_iter()
            .map(|(k, v)| (Value::Integer(k), v))
            .collect();
        cbor::to_vec(&map).unwrap()
    }

    fn versions() -> Value {
        Value::Array(vec![Value::Text("FIDO_2_0".into())])
    }

    #[test]
    fn accepts_minimal_get_info() {
        let bytes = get_info(vec![(0x01, versions()), (0x03, Value::Bytes(vec![0; 16]))]);
        let info: GetInfoResponse = cbor::from_slice(&bytes).unwrap();
        assert_eq!(info.versions, vec!["FIDO_2_0".to_string()]);
    }

    #[test]
    fn ignores_other_members() {
        let bytes = get_info(vec![
            (0x01, versions()),
            (0x03, Value::Bytes(vec![0; 16])),
            (0x05, Value::Integer(1200)),
        ]);
        assert!(cbor::from_slice::<GetInfoResponse>(&bytes).is_ok());
    }

    #[test]
    fn rejects_missing_aaguid() {
        let bytes = get_info(vec![(0x01, versions())]);
        assert!(cbor::from_slice::<GetInfoResponse>(&bytes).is_err());
    }

    #[test]
    fn rejects_mistyped_versions() {
        let bytes = get_info(vec![
            (0x01, Value::Integer(2)),
            (0x03, Value::Bytes(vec![0; 16])),
        ]);
        assert!(cbor::from_slice::<GetInfoResponse>(&bytes).is_err());
    }

    #[test]
    fn rejects_non_map() {
        assert!(cbor::from_slice::<GetInfoResponse>(&[0x01]).is_err());
    }
}
