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

pub(crate) trait CborSerialize {
    fn to_vec(&self) -> Result<Vec<u8>, CborError>;
}

impl<T> CborSerialize for T
where
    T: Serialize,
{
    fn to_vec(&self) -> Result<Vec<u8>, CborError> {
        serde_cbor::ser::to_vec(self).map_err(CborError::from)
    }
}

pub(crate) trait CborDeserialize<T>: Sized + serde::de::DeserializeOwned {
    fn from_reader<R: std::io::Read>(reader: R) -> Result<Self, CborError>;
    fn from_slice(slice: &[u8]) -> Result<Self, CborError>;
}

impl<T> CborDeserialize<T> for T
where
    T: for<'de> serde::Deserialize<'de>,
{
    fn from_reader<R: std::io::Read>(reader: R) -> Result<Self, CborError> {
        serde_cbor::de::from_reader(reader).map_err(CborError::from)
    }

    fn from_slice(slice: &[u8]) -> Result<Self, CborError> {
        serde_cbor::de::from_slice(slice).map_err(CborError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_indexed::{DeserializeIndexed, SerializeIndexed};

    #[derive(Debug, PartialEq, SerializeIndexed, DeserializeIndexed)]
    #[serde_indexed(offset = 1)]
    struct TestStruct {
        pub a: u8,
        pub b: u8,
    }

    #[test]
    fn test_deserialize_indexed_with_extra_field() {
        // Map: 1 => 10, 2 => 20, 3 => 99 (unexpected)
        let value = TestStruct { a: 10, b: 20 };
        let mut map = std::collections::BTreeMap::new();
        map.insert(1, 10u8);
        map.insert(2, 20u8);
        map.insert(3, 99u8); // unexpected field

        let cbor = map.to_vec().unwrap();
        let result = TestStruct::from_slice(&cbor).unwrap();
        assert_eq!(result, value);
    }
}
