use std::convert::TryFrom;
use std::io::{BufRead, Cursor as IOCursor, Error as IOError, ErrorKind as IOErrorKind, Read};
use std::time::Duration;

use byteorder::{BigEndian, ReadBytesExt};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::proto::ctap1::apdu::{ApduResponse, ApduResponseStatus};
use crate::proto::ctap2::Ctap2Transport;
use crate::webauthn::CtapError;

#[derive(Debug, Clone, Copy)]
pub enum Ctap1Transport {
    Bt,
    Ble,
    Nfc,
    Usb,
}

impl TryFrom<&Ctap2Transport> for Ctap1Transport {
    type Error = CtapError;
    fn try_from(ctap2: &Ctap2Transport) -> Result<Ctap1Transport, Self::Error> {
        match ctap2 {
            Ctap2Transport::Ble => Ok(Ctap1Transport::Ble),
            Ctap2Transport::Usb => Ok(Ctap1Transport::Usb),
            Ctap2Transport::Nfc => Ok(Ctap1Transport::Nfc),
            Ctap2Transport::Internal => Err(CtapError::UnsupportedOption),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Ctap1Version {
    U2fV2,
}

#[derive(Debug, Clone)]
pub struct Ctap1RegisteredKey {
    pub version: Ctap1Version,
    pub key_handle: Vec<u8>,
    pub transports: Option<Vec<Ctap1Transport>>,
    pub app_id: Option<String>,
}

impl Ctap1RegisteredKey {
    pub fn new_u2f_v2(key_handle: &[u8]) -> Ctap1RegisteredKey {
        Ctap1RegisteredKey {
            version: Ctap1Version::U2fV2,
            key_handle: Vec::from(key_handle),
            transports: None,
            app_id: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Ctap1RegisterRequest {
    pub version: Ctap1Version,
    pub app_id_hash: Vec<u8>,
    pub challenge: Vec<u8>,
    pub registered_keys: Vec<Ctap1RegisteredKey>,
    pub timeout: Duration,
    pub require_user_presence: bool,
}

impl Ctap1RegisterRequest {
    pub fn new_u2f_v2(
        app_id: &str,
        challenge: &[u8],
        registered_keys: Vec<Ctap1RegisteredKey>,
        timeout: Duration,
        require_user_presence: bool,
    ) -> Ctap1RegisterRequest {
        let mut hasher = Sha256::default();
        hasher.update(app_id);
        let app_id_hash = hasher.finalize().to_vec();

        Ctap1RegisterRequest {
            version: Ctap1Version::U2fV2,
            app_id_hash,
            challenge: Vec::from(challenge),
            registered_keys,
            timeout,
            require_user_presence,
        }
    }

    pub fn dummy(timeout: Duration) -> Self {
        Ctap1RegisterRequest {
            version: Ctap1Version::U2fV2,
            app_id_hash: vec![0; 32],
            challenge: vec![0; 32],
            registered_keys: Vec::new(),
            timeout,
            require_user_presence: true,
        }
    }
}

#[derive(Debug)]
pub struct Ctap1RegisterResponse {
    pub version: Ctap1Version,
    pub public_key: Vec<u8>,
    pub key_handle: Vec<u8>,
    pub attestation: Vec<u8>,
    pub signature: Vec<u8>,
}

impl TryFrom<ApduResponse> for Ctap1RegisterResponse {
    type Error = IOError;

    fn try_from(apdu: ApduResponse) -> Result<Self, Self::Error> {
        if apdu.status()? != ApduResponseStatus::NoError {
            return Err(IOError::new(
                IOErrorKind::InvalidInput,
                "APDU packets need to have status NoError to be converted..",
            ));
        }

        let data = apdu.data.ok_or(IOError::new(
            IOErrorKind::InvalidInput,
            "Emtpy APDU packet.",
        ))?;

        let mut cursor = IOCursor::new(data);
        cursor.consume(1); // Reserved bytes.

        let mut public_key = vec![0u8; 65];
        cursor.read_exact(&mut public_key)?;

        let key_handle_len = cursor.read_u8()? as u64;
        let mut key_handle = vec![0u8; key_handle_len as usize];
        cursor.read_exact(&mut key_handle)?;

        let mut remaining = vec![];
        cursor.read_to_end(&mut remaining)?;

        let (signature, _) = X509Certificate::from_der(&remaining).or(Err(IOError::new(
            IOErrorKind::InvalidData,
            "Failed to parse X509 attestation data",
        )))?;
        let signature = Vec::from(signature);
        let attestation = Vec::from(&remaining[0..remaining.len() - signature.len()]);

        Ok(Ctap1RegisterResponse {
            version: Ctap1Version::U2fV2,
            public_key,
            key_handle,
            attestation,
            signature,
        })
    }
}

impl Ctap1RegisterResponse {
    pub fn as_registered_key(&self) -> Result<Ctap1RegisteredKey, IOError> {
        Ok(Ctap1RegisteredKey::new_u2f_v2(&self.key_handle))
    }
}

#[derive(Debug, Clone)]
pub struct Ctap1SignRequest {
    pub app_id_hash: Vec<u8>,
    pub challenge: Vec<u8>,
    pub key_handle: Vec<u8>,
    pub timeout: Duration,
    pub require_user_presence: bool,
}

impl Ctap1SignRequest {
    pub fn new(
        app_id: &str,
        challenge: &[u8],
        key_handle: &[u8],
        timeout: Duration,
        require_user_presence: bool,
    ) -> Ctap1SignRequest {
        let mut hasher = Sha256::default();
        hasher.update(app_id);
        let app_id_hash = hasher.finalize().to_vec();

        Ctap1SignRequest {
            app_id_hash: app_id_hash,
            challenge: Vec::from(challenge),
            key_handle: Vec::from(key_handle),
            timeout,
            require_user_presence,
        }
    }

    pub fn new_preflight(
        app_id_hash: &[u8],
        challenge: &[u8],
        key_handle: &[u8],
        timeout: Duration,
    ) -> Ctap1SignRequest {
        Ctap1SignRequest {
            app_id_hash: Vec::from(app_id_hash),
            challenge: Vec::from(challenge),
            key_handle: Vec::from(key_handle),
            timeout,
            require_user_presence: false,
        }
    }
}

#[derive(Debug)]
pub struct Ctap1VersionRequest {}

impl Ctap1VersionRequest {
    pub fn new() -> Ctap1VersionRequest {
        Ctap1VersionRequest {}
    }
}

#[derive(Debug)]
pub struct Ctap1VersionResponse {
    pub version: Ctap1Version,
}

impl TryFrom<ApduResponse> for Ctap1VersionResponse {
    type Error = IOError;

    fn try_from(apdu: ApduResponse) -> Result<Self, Self::Error> {
        if apdu.status()? != ApduResponseStatus::NoError {
            return Err(IOError::new(
                IOErrorKind::InvalidInput,
                "APDU packets need to have status NoError to be converted..",
            ));
        }

        let data = apdu.data.ok_or(IOError::new(
            IOErrorKind::InvalidInput,
            "Emtpy APDU packet.",
        ))?;

        let version_string = String::from_utf8(data).or(Err(IOError::new(
            IOErrorKind::InvalidInput,
            "Invalid UTF-8 bytes in CTAP1 version string",
        )))?;

        let version = match version_string.as_str() {
            "U2F_V2" => Ctap1Version::U2fV2,
            _ => {
                return Err(IOError::new(
                    IOErrorKind::InvalidInput,
                    format!("Invalid CTAP1 version string: {:}", version_string),
                ))
            }
        };

        Ok(Ctap1VersionResponse { version })
    }
}

#[derive(Debug, Clone)]
pub struct Ctap1SignResponse {
    pub user_presence_verified: bool,
    pub counter: u32,
    pub signature: Vec<u8>,
}

impl TryFrom<ApduResponse> for Ctap1SignResponse {
    type Error = IOError;

    fn try_from(apdu: ApduResponse) -> Result<Self, Self::Error> {
        if apdu.status()? != ApduResponseStatus::NoError {
            return Err(IOError::new(
                IOErrorKind::InvalidInput,
                "APDU packets need to have status NoError to be converted..",
            ));
        }

        let data = apdu.data.ok_or(IOError::new(
            IOErrorKind::InvalidInput,
            "Emtpy APDU packet.",
        ))?;

        let mut cursor = IOCursor::new(data);
        let user_presence_verified = match cursor.read_u8()? {
            0x01 => true,
            _ => false,
        };
        let counter = cursor.read_u32::<BigEndian>()?;

        let mut signature = vec![];
        cursor.read_to_end(&mut signature)?;

        Ok(Ctap1SignResponse {
            user_presence_verified,
            counter,
            signature,
        })
    }
}

pub trait Preflight<P>: Sized {
    /// Modify request in place, removing items in exclusion list, in favour of generating new pre-fligh requests.
    fn preflight(&self) -> Result<(Self, Vec<P>), CtapError>;
}

impl Preflight<Ctap1SignRequest> for Ctap1RegisterRequest {
    fn preflight(&self) -> Result<(Self, Vec<Ctap1SignRequest>), CtapError> {
        let preflight_requests: Vec<Ctap1SignRequest> = self
            .registered_keys
            .iter()
            .map(|registered_key| {
                Ctap1SignRequest::new_preflight(
                    &self.app_id_hash,
                    &[0u8; 32],
                    &registered_key.key_handle,
                    self.timeout,
                )
            })
            .collect();

        let mut modified = self.to_owned();
        modified.registered_keys = vec![];
        Ok((modified, preflight_requests))
    }
}

#[cfg(test)]
mod tests {
    use crate::proto::ctap1::apdu::ApduResponse;
    use crate::proto::ctap1::Ctap1RegisterResponse;
    use std::convert::TryInto;

    #[test]
    fn register_response_apdu_to_ctap1() {
        let apdu = hex::decode("05046DDBE3C25D974C9A403D6C648ED41C219D44734C43986B4053B325BE01C31E28F146731E5C21BA0E0E1938DA4C1FECAD650A2971A13CF6076BF52B52C19F8D0E40602CFD267868E84D4852BD5B008BC6CE0211D4858C8A647328A13B7D5C0A42B3893D63A58FCA7BD3EBB74F55CE537195DFF0113D4C561BBB7DFAC0C0ECD1AFB53082015930820100A003020102020102300A06082A8648CE3D0403023028311530130603550403130C5365637572697479204B6579310F300D060355040A1306476F6F676C653022180F32303030303130313030303030305A180F32303939313233313233353935395A3028311530130603550403130C5365637572697479204B6579310F300D060355040A1306476F6F676C653059301306072A8648CE3D020106082A8648CE3D030107034200040393AF897BE858E88C1953876A1A538477C4DA6E6EA14ACF0A2FD89A4DCCF95878A8CD2929029CC1D794BFFB9C37547CBBB5BB31AB3A6756ACF74F123CECD45CA31730153013060B2B0601040182E51C020101040403020470300A06082A8648CE3D040302034700304402207F958ABE6CF08CB2E9A03774D52DF8C0EA261E1AC0C283409FEDD8D36DFAF09302204EEB7501C720428D206E1B092D8D26CA8536B70F5F09AEA99562390BEF1BA7EC3044022031413D6E238A5F998B26B3931655C411847D99776B6E5CF15AA2E11BFAF325F00220098745DA82C11BB242934BAC6AE95155EAAD68520D695D46982DA9B2C94F94E3").unwrap();
        let apdu = ApduResponse::new_success(&apdu);
        let decoded: Ctap1RegisterResponse = apdu.try_into().unwrap();

        assert_eq!(decoded.public_key, hex::decode("046DDBE3C25D974C9A403D6C648ED41C219D44734C43986B4053B325BE01C31E28F146731E5C21BA0E0E1938DA4C1FECAD650A2971A13CF6076BF52B52C19F8D0E").unwrap());
        assert_eq!(decoded.key_handle, hex::decode("602CFD267868E84D4852BD5B008BC6CE0211D4858C8A647328A13B7D5C0A42B3893D63A58FCA7BD3EBB74F55CE537195DFF0113D4C561BBB7DFAC0C0ECD1AFB5").unwrap());
        assert_eq!(decoded.attestation, hex::decode("3082015930820100A003020102020102300A06082A8648CE3D0403023028311530130603550403130C5365637572697479204B6579310F300D060355040A1306476F6F676C653022180F32303030303130313030303030305A180F32303939313233313233353935395A3028311530130603550403130C5365637572697479204B6579310F300D060355040A1306476F6F676C653059301306072A8648CE3D020106082A8648CE3D030107034200040393AF897BE858E88C1953876A1A538477C4DA6E6EA14ACF0A2FD89A4DCCF95878A8CD2929029CC1D794BFFB9C37547CBBB5BB31AB3A6756ACF74F123CECD45CA31730153013060B2B0601040182E51C020101040403020470300A06082A8648CE3D040302034700304402207F958ABE6CF08CB2E9A03774D52DF8C0EA261E1AC0C283409FEDD8D36DFAF09302204EEB7501C720428D206E1B092D8D26CA8536B70F5F09AEA99562390BEF1BA7EC").unwrap());
        assert_eq!(decoded.signature, hex::decode("3044022031413D6E238A5F998B26B3931655C411847D99776B6E5CF15AA2E11BFAF325F00220098745DA82C11BB242934BAC6AE95155EAAD68520D695D46982DA9B2C94F94E3").unwrap());
    }
}
