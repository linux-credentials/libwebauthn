use serde::Serialize;
use serde_cbor_2 as serde_cbor;

#[derive(thiserror::Error, Debug)]
pub enum CborError {
    #[error("serde_cbor serialization error: {0}")]
    SerdeCbor(#[from] serde_cbor::Error),
}

impl PartialEq for CborError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (CborError::SerdeCbor(e1), CborError::SerdeCbor(e2)) => {
                e1.to_string() == e2.to_string()
            }
        }
    }
}

pub(crate) type Value = serde_cbor::Value;

pub(crate) fn to_vec<T>(serializable: &T) -> Result<Vec<u8>, CborError>
where
    T: Serialize,
{
    serde_cbor::ser::to_vec(serializable).map_err(CborError::from)
}

pub(crate) fn from_reader<T, R>(reader: R) -> Result<T, CborError>
where
    T: for<'de> serde::Deserialize<'de>,
    R: std::io::Read,
{
    serde_cbor::de::from_reader(reader).map_err(CborError::from)
}

pub(crate) fn from_slice<T>(slice: &[u8]) -> Result<T, CborError>
where
    T: for<'de> serde::Deserialize<'de>,
{
    serde_cbor::de::from_slice(slice).map_err(CborError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use serde_cbor;
    use serde_indexed::{DeserializeIndexed, SerializeIndexed};
    use std::collections::BTreeMap;

    #[derive(Debug, PartialEq, SerializeIndexed, DeserializeIndexed)]
    struct IndexedStruct {
        #[serde(index = 0x01)]
        pub a: u8,
        #[serde(index = 0x02)]
        pub b: u8,
    }

    #[test]
    fn test_deserialize_indexed() {
        let expected = IndexedStruct { a: 10, b: 20 };
        let mut map = BTreeMap::new();
        map.insert(1, 10u8);
        map.insert(2, 20u8);

        let cbor = to_vec(&map).unwrap();
        let result: IndexedStruct = from_slice(&cbor).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_serialize_indexed() {
        let indexed_struct = IndexedStruct { a: 10, b: 20 };
        let serialized = to_vec(&indexed_struct).unwrap();
        let expected = serde_cbor::to_vec(&indexed_struct).unwrap();
        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_deserialize_indexed_ignore_extra_field() {
        // Map: 1 => 10, 2 => 20, 3 => 99 (unexpected)
        let expected = IndexedStruct { a: 10, b: 20 };
        let mut map = BTreeMap::new();
        map.insert(1, 10u8);
        map.insert(2, 20u8);
        map.insert(3, 99u8); // unexpected field

        let cbor = to_vec(&map).unwrap();
        let result: IndexedStruct = from_slice(&cbor).unwrap();
        assert_eq!(result, expected);
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct NamedStruct {
        #[serde(rename = "key")]
        pub value: u8,
    }

    #[test]
    fn test_deserialize_named() {
        let expected = NamedStruct { value: 10 };
        let mut map = BTreeMap::new();
        map.insert("key", 10u8);

        let cbor = to_vec(&map).unwrap();
        let result: NamedStruct = from_slice(&cbor).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_serialize_named() {
        let named_struct = NamedStruct { value: 10 };
        let serialized = to_vec(&named_struct).unwrap();
        let expected = serde_cbor::to_vec(&named_struct).unwrap();
        assert_eq!(serialized, expected);
    }

    #[derive(Debug, PartialEq, SerializeIndexed, DeserializeIndexed)]
    struct NestedStruct {
        #[serde(index = 0x00)]
        pub inner: NamedStruct,
    }

    #[test]
    fn test_deserialize_nested() {
        let expected = NestedStruct {
            inner: NamedStruct { value: 10 },
        };

        let mut inner_map = BTreeMap::new();
        inner_map.insert("key", 10u8);
        let mut outer_map = BTreeMap::new();
        outer_map.insert(0, inner_map);

        let cbor = to_vec(&outer_map).unwrap();
        let result: NestedStruct = from_slice(&cbor).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_serialize_nested() {
        let nested_struct = NestedStruct {
            inner: NamedStruct { value: 10 },
        };
        let serialized = to_vec(&nested_struct).unwrap();
        let expected = serde_cbor::to_vec(&nested_struct).unwrap();
        assert_eq!(serialized, expected);
    }
}
