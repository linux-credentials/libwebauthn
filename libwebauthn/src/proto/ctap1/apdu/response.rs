use std::convert::{TryFrom, TryInto};
use std::io::{Cursor as IOCursor, Error as IOError, ErrorKind as IOErrorKind};

use byteorder::{BigEndian, ReadBytesExt};
use num_enum::{IntoPrimitive, TryFromPrimitive};

#[derive(Debug, PartialEq)]
pub struct ApduResponse {
    pub data: Option<Vec<u8>>,
    sw1: u8,
    sw2: u8,
}

#[derive(Debug, IntoPrimitive, TryFromPrimitive, Copy, Clone, PartialEq)]
#[repr(u16)]
pub enum ApduResponseStatus {
    NoError = 0x9000,
    UserPresenceTestFailed = 0x6985,
    InvalidKeyHandle = 0x6A80,
    InvalidRequestLength = 0x6700,
    InvalidClassByte = 0x6E00,
    InvalidInstruction = 0x6D00,
}

impl ApduResponse {
    pub fn new_success(data: &[u8]) -> Self {
        Self {
            data: Some(Vec::from(data)),
            sw1: 0x90,
            sw2: 0x00,
        }
    }

    pub fn status(&self) -> Result<ApduResponseStatus, IOError> {
        let mut cursor = IOCursor::new(vec![self.sw1, self.sw2]);
        let code = cursor.read_u16::<BigEndian>()?;

        code.try_into().or(Err(IOError::new(
            IOErrorKind::InvalidData,
            format!("Unknown APDU response code returned: {:x}", code),
        )))
    }
}

impl TryFrom<&Vec<u8>> for ApduResponse {
    type Error = IOError;
    fn try_from(packet: &Vec<u8>) -> Result<Self, Self::Error> {
        if packet.len() < 2 {
            return Err(IOError::new(
                IOErrorKind::InvalidData,
                "Apdu response packets must contain at least 2 bytes.",
            ));
        }

        let data = if packet.len() > 2 {
            Some(Vec::from(&packet[0..packet.len() - 2]))
        } else {
            None
        };
        let (sw1, sw2) = (packet[packet.len() - 2], packet[packet.len() - 1]);

        Ok(Self { data, sw1, sw2 })
    }
}

#[cfg(test)]
mod tests {
    use crate::proto::ctap1::apdu::response::ApduResponseStatus;
    use crate::proto::ctap1::apdu::ApduResponse;
    use std::convert::TryInto;
    use std::io::{Error as IOError, ErrorKind as IOErrorKind};

    #[test]
    fn apdu_from_status_only_packet() {
        let packet: &Vec<u8> = &vec![0x69, 0x85];
        let apdu: ApduResponse = packet.try_into().unwrap();
        assert_eq!(
            apdu.status().unwrap(),
            ApduResponseStatus::UserPresenceTestFailed
        );
        assert_eq!(apdu.data, None);
    }

    #[test]
    fn apdu_from_full_packet() {
        let packet: &Vec<u8> = &vec![0x01, 0x02, 0x03, 0x90, 0x00];
        let apdu: ApduResponse = packet.try_into().unwrap();
        assert_eq!(apdu.status().unwrap(), ApduResponseStatus::NoError);
        assert_eq!(apdu.data, Some(vec![0x01, 0x02, 0x03]));
    }

    #[test]
    fn apdu_from_invalid_packet() {
        let packet: &Vec<u8> = &vec![0xB0];
        let apdu: Result<ApduResponse, IOErrorKind> =
            packet.try_into().map_err(|ioe: IOError| ioe.kind());
        assert_eq!(apdu, Err(IOErrorKind::InvalidData));
    }
}
