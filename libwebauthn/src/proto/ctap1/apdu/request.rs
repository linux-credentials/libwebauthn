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

const CLA: u8 = 0x00;

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
            data: data.map(Vec::from),
            response_max_length,
        }
    }

    pub fn raw_short(&self) -> Result<Vec<u8>, IOError> {
        let mut raw: Vec<u8> = vec![CLA, self.ins, self.p1, self.p2];

        if let Some(data) = &self.data {
            if data.len() > APDU_SHORT_MAX_DATA {
                return Err(IOError::new(
                    IOErrorKind::InvalidData,
                    format!(
                        "Unable to serialize {} bytes of data in APDU short form.",
                        data.len()
                    ),
                ));
            } else if data.is_empty() {
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
        let mut raw: Vec<u8> = vec![CLA, self.ins, self.p1, self.p2];

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

        // Per ISO 7816-4 and FIDO U2F Raw Message Formats §3, §4: when a
        // response is expected, append a 2-byte extended-length Le.
        // Le=0x0000 is the wildcard meaning "up to 65536 bytes".
        if let Some(le) = self.response_max_length {
            let le_field = if le >= 0x1_0000 { 0u16 } else { le as u16 };
            raw.write_u16::<BigEndian>(le_field)?;
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
        data.push(request.key_handle.len() as u8);
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

    #[test]
    fn apdu_raw_long_with_data_and_le() {
        // Case 4 Extended APDU: header + Lc(3 BE) + data + Le(2 BE).
        let data: Vec<u8> = vec![0xAA, 0xBB, 0xCC];
        let apdu = ApduRequest::new(0x01, 0x02, 0x03, Some(&data), Some(0x100));
        assert_eq!(
            apdu.raw_long().unwrap(),
            [
                0x00, 0x01, 0x02, 0x03, // CLA, INS, P1, P2
                0x00, 0x00, 0x03, // Lc = 3 (extended)
                0xAA, 0xBB, 0xCC, // payload
                0x01, 0x00, // Le = 256 (big-endian)
            ],
        );
    }

    #[test]
    fn apdu_raw_long_no_data_with_le() {
        // Case 2 Extended APDU: header + Lc=0 (3 BE) + Le(2 BE).
        let apdu = ApduRequest::new(0x01, 0x02, 0x03, None, Some(0x100));
        assert_eq!(
            apdu.raw_long().unwrap(),
            [
                0x00, 0x01, 0x02, 0x03, // CLA, INS, P1, P2
                0x00, 0x00, 0x00, // Lc = 0 (extended)
                0x01, 0x00, // Le = 256 (big-endian)
            ],
        );
    }

    #[test]
    fn apdu_raw_long_with_data_and_le_wildcard() {
        // Le >= 65536 encodes as 0x0000 wildcard per ISO 7816-4.
        let data: Vec<u8> = vec![0xAA];
        let apdu = ApduRequest::new(0x01, 0x02, 0x03, Some(&data), Some(0x1_0000));
        let serialized = apdu.raw_long().unwrap();
        let trailing = &serialized[serialized.len() - 2..];
        assert_eq!(trailing, &[0x00, 0x00], "Le wildcard for max length");
    }

    #[test]
    fn apdu_raw_long_register_request_is_case_4() {
        // Mirrors the encoding produced by `From<&Ctap1RegisterRequest> for ApduRequest`.
        let mut payload = vec![0x11u8; 32]; // challenge
        payload.extend(vec![0x22u8; 32]); // app id hash
        let apdu = ApduRequest::new(
            0x01, // U2F_REGISTER
            0x03, // CONTROL_BYTE_ENFORCE_UP_AND_SIGN
            0x00,
            Some(&payload),
            Some(0x100),
        );
        let serialized = apdu.raw_long().unwrap();
        // Header (4) + extended Lc (3) + payload (64) + extended Le (2)
        assert_eq!(serialized.len(), 4 + 3 + 64 + 2);
        // Must terminate with the 2-byte Le; otherwise it is Case 3 and
        // strict authenticators reject it.
        let trailing = &serialized[serialized.len() - 2..];
        assert_eq!(
            trailing,
            &[0x01, 0x00],
            "REGISTER must be Case 4 with Le=256 (extended)",
        );
    }
}
