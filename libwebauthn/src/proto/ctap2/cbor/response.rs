use crate::proto::error::CtapError;

use std::convert::TryFrom;
use std::io::{Error as IOError, ErrorKind as IOErrorKind};

#[derive(Debug, Clone)]
pub struct CborResponse {
    pub status_code: CtapError,
    pub data: Option<Vec<u8>>,
}

impl CborResponse {
    pub fn new_success_from_slice(slice: &[u8]) -> Self {
        Self {
            status_code: CtapError::Ok,
            data: match slice.len() {
                0 => None,
                _ => Some(Vec::from(slice)),
            },
        }
    }
}

impl TryFrom<&Vec<u8>> for CborResponse {
    type Error = IOError;
    fn try_from(packet: &Vec<u8>) -> Result<Self, Self::Error> {
        let (status_byte, body) = packet.split_first().ok_or_else(|| {
            IOError::new(
                IOErrorKind::InvalidData,
                "Cbor response packets must contain at least 1 byte.",
            )
        })?;

        let status_code = CtapError::from(*status_byte);

        let data = if body.is_empty() {
            None
        } else {
            Some(Vec::from(body))
        };
        Ok(CborResponse { status_code, data })
    }
}

#[cfg(test)]
mod tests {
    use super::CborResponse;
    use crate::proto::error::CtapError;
    use std::convert::TryFrom;

    #[test]
    fn unknown_status_byte_is_preserved() {
        let response = CborResponse::try_from(&vec![0xDEu8]).expect("must not be a framing error");
        assert_eq!(response.status_code, CtapError::Unknown(0xDE));
        assert!(response.data.is_none());
    }

    #[test]
    fn unknown_status_byte_keeps_body() {
        let response =
            CborResponse::try_from(&vec![0xF5u8, 0xAA, 0xBB]).expect("must not be a framing error");
        assert_eq!(response.status_code, CtapError::Unknown(0xF5));
        assert_eq!(response.data.as_deref(), Some(&[0xAA, 0xBB][..]));
    }
}
