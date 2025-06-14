use serde::Serialize;

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
    use serde_cbor;
    use serde_indexed::{DeserializeIndexed, SerializeIndexed};

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
        let mut map = std::collections::BTreeMap::new();
        map.insert(1, 10u8);
        map.insert(2, 20u8);

        let cbor = to_vec(&map).unwrap();
        let result = from_slice::<IndexedStruct>(&cbor).unwrap();
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
        let mut map = std::collections::BTreeMap::new();
        map.insert(1, 10u8);
        map.insert(2, 20u8);
        map.insert(3, 99u8); // unexpected field

        let cbor = to_vec(&map).unwrap();
        let result = from_slice::<IndexedStruct>(&cbor).unwrap();
        assert_eq!(result, expected);
    }
}
