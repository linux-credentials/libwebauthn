use std::io::{Error as IOError, ErrorKind as IOErrorKind};

use byteorder::{BigEndian, WriteBytesExt};

use crate::proto::ctap1::model::Ctap1VersionRequest;
use crate::proto::ctap1::{Ctap1RegisterRequest, Ctap1SignRequest};

const APDU_SHORT_MAX_DATA: usize = 0x100;
const APDU_SHORT_MAX_LE: usize = 0x100;
const APDU_SHORT_LE: usize = APDU_SHORT_MAX_LE;

const APDI_LONG_MAX_DATA: usize = 0xFF_FF_FF;

const U2F_REGISTER: u8 = 0x01;
const U2F_AUTHENTICATE: u8 = 0x02;
const U2F_VERSION: u8 = 0x03;

const _CONTROL_BYTE_CHECK_ONLY: u8 = 0x07;
const CONTROL_BYTE_ENFORCE_UP_AND_SIGN: u8 = 0x03;
const CONTROL_BYTE_DONT_ENFORCE_UP_AND_SIGN: u8 = 0x08;

#[derive(Debug)]
pub struct ApduRequest {
    pub(crate) ins: u8,
    pub(crate) p1: u8,
    pub(crate) p2: u8,
    pub(crate) data: Option<Vec<u8>>,
    pub(crate) response_max_length: Option<usize>,
}

impl ApduRequest {
    pub fn new(
        ins: u8,
        p1: u8,
        p2: u8,
        data: Option<&[u8]>,
        response_max_length: Option<usize>,
    ) -> Self {
        Self {
            ins,
            p1,
            p2,
            data: if let Some(bytes) = data {
                Some(Vec::from(bytes))
            } else {
                None
            },
            response_max_length,
        }
    }

    pub fn raw_short(&self) -> Result<Vec<u8>, IOError> {
        let mut raw: Vec<u8> = Vec::new();
        raw.push(0x00); // CLA
        raw.push(self.ins);
        raw.push(self.p1);
        raw.push(self.p2);

        if let Some(data) = &self.data {
            if data.len() > APDU_SHORT_MAX_DATA {
                return Err(IOError::new(
                    IOErrorKind::InvalidData,
                    format!(
                        "Unable to serialize {} bytes of data in APDU short form.",
                        data.len()
                    ),
                ));
            } else if data.len() == 0 {
                return Err(IOError::new(
                    IOErrorKind::InvalidData,
                    "Cannot serialize an empty payload.",
                ));
            };

            raw.push(if data.len() != APDU_SHORT_MAX_DATA {
                data.len() as u8
            } else {
                0
            });
            raw.extend(data);
        }

        if let Some(le) = self.response_max_length {
            if le > APDU_SHORT_MAX_LE {
                return Err(IOError::new(
                    IOErrorKind::InvalidData,
                    format!("Unable to serialize L_e value ({}) in APDU short form.", le),
                ));
            }

            raw.push(if le == APDU_SHORT_MAX_LE { 0 } else { le as u8 });
        }
        Ok(raw)
    }

    pub fn raw_long(&self) -> Result<Vec<u8>, IOError> {
        let mut raw: Vec<u8> = Vec::new();
        raw.push(0x00); // CLA
        raw.push(self.ins);
        raw.push(self.p1);
        raw.push(self.p2);

        if let Some(data) = &self.data {
            if data.len() > APDI_LONG_MAX_DATA {
                return Err(IOError::new(
                    IOErrorKind::InvalidData,
                    format!(
                        "Unable to serialize {} bytes of data in APDU long form.",
                        data.len()
                    ),
                ));
            }
            raw.write_u24::<BigEndian>(data.len() as u32)?;
            raw.extend(data);
        } else {
            raw.write_u24::<BigEndian>(0)?;
        }

        Ok(raw)
    }
}

impl From<&Ctap1RegisterRequest> for ApduRequest {
    fn from(request: &Ctap1RegisterRequest) -> Self {
        let mut data = request.challenge.clone();
        data.extend(&request.app_id_hash);
        Self::new(
            U2F_REGISTER,
            CONTROL_BYTE_ENFORCE_UP_AND_SIGN,
            0x00,
            Some(&data),
            Some(APDU_SHORT_LE),
        )
    }
}

impl From<&Ctap1VersionRequest> for ApduRequest {
    fn from(_: &Ctap1VersionRequest) -> Self {
        Self::new(U2F_VERSION, 0x00, 0x00, None, Some(APDU_SHORT_LE))
    }
}

impl From<&Ctap1SignRequest> for ApduRequest {
    fn from(request: &Ctap1SignRequest) -> Self {
        let p1 = if request.require_user_presence {
            CONTROL_BYTE_ENFORCE_UP_AND_SIGN
        } else {
            CONTROL_BYTE_DONT_ENFORCE_UP_AND_SIGN
        };
        let mut data = request.challenge.clone();
        data.extend(&request.app_id_hash);
        data.write_u8(request.key_handle.len() as u8).unwrap();
        data.extend(&request.key_handle);
        Self::new(U2F_AUTHENTICATE, p1, 0x00, Some(&data), Some(APDU_SHORT_LE))
    }
}

#[cfg(test)]
mod tests {
    use crate::proto::ctap1::apdu::ApduRequest;

    #[test]
    fn apdu_raw_short_no_data() {
        let apdu = ApduRequest::new(0x01, 0x02, 0x03, None, None);
        assert_eq!(apdu.raw_short().unwrap(), [0x00, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn apdu_raw_short_no_data_le() {
        let apdu = ApduRequest::new(0x01, 0x02, 0x03, None, Some(0x42));
        assert_eq!(apdu.raw_short().unwrap(), [0x00, 0x01, 0x02, 0x03, 0x42]);
    }

    #[test]
    fn apdu_raw_short_with_data() {
        let data = &[0xAA, 0xBB, 0xCC];
        let apdu = ApduRequest::new(0x03, 0x02, 0x01, Some(data), None);
        assert_eq!(
            apdu.raw_short().unwrap(),
            [0x00, 0x03, 0x02, 0x01, 0x03, 0xAA, 0xBB, 0xCC]
        );
    }

    #[test]
    fn apdu_raw_short_with_data_le() {
        let data = &[0xAA, 0xBB, 0xCC];
        let apdu = ApduRequest::new(0x03, 0x02, 0x01, Some(data), Some(0x42));
        assert_eq!(
            apdu.raw_short().unwrap(),
            [0x00, 0x03, 0x02, 0x01, 0x03, 0xAA, 0xBB, 0xCC, 0x42]
        );
    }

    #[test]
    fn apdu_raw_short_with_max_len_data() {
        let data: Vec<u8> = vec![0xF1; 256];
        let apdu = ApduRequest::new(0x0A, 0x0B, 0x0C, Some(&data), None);
        let serialized = apdu.raw_short().unwrap();
        assert_eq!(&serialized[0..5], &[0x00, 0x0A, 0x0B, 0x0C, 0x00]);
        assert_eq!(&serialized[5..261], data.as_slice());
    }

    #[test]
    fn apdu_raw_long_no_data() {
        let apdu = ApduRequest::new(0x01, 0x02, 0x03, None, None);
        assert_eq!(
            apdu.raw_long().unwrap(),
            [0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00],
        );
    }

    #[test]
    fn apdu_raw_long_with_data() {
        let data: Vec<u8> = vec![0xF1; 512];
        let apdu = ApduRequest::new(0x01, 0x02, 0x03, Some(&data), None);
        let serialized = apdu.raw_long().unwrap();
        assert_eq!(
            &serialized[0..7],
            &[0x00, 0x01, 0x02, 0x03, 0x00, 0x02, 0x00],
        );
        assert_eq!(&serialized[7..519], data.as_slice());
    }
}
