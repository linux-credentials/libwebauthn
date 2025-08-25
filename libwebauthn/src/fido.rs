use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use cosey::PublicKey;
use serde::{
    de::{DeserializeOwned, Error as DesError, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_bytes::ByteBuf;
use std::{
    fmt,
    io::{Cursor, Read},
    marker::PhantomData,
};
use tracing::{error, warn};

use crate::proto::ctap2::cbor;
use crate::{
    proto::{
        ctap2::{Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialType},
        CtapError,
    },
    webauthn::{Error, PlatformError},
};

#[derive(Debug, PartialEq, Eq)]
pub enum FidoProtocol {
    FIDO2,
    U2F,
}

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
#[repr(u8)]
pub enum FidoRevision {
    V2 = 0x20,
    U2fv12 = 0x40,
    U2fv11 = 0x80,
}

impl From<FidoRevision> for FidoProtocol {
    fn from(revision: FidoRevision) -> Self {
        match revision {
            FidoRevision::V2 => FidoProtocol::FIDO2,
            FidoRevision::U2fv11 | FidoRevision::U2fv12 => FidoProtocol::U2F,
        }
    }
}

bitflags! {
    #[derive(Debug, Clone)]
    pub struct AuthenticatorDataFlags: u8 {
        const USER_PRESENT = 0x01;
        const RFU_1 = 0x02;
        const USER_VERIFIED = 0x04;
        const RFU_2_1 = 0x08;
        const RFU_2_2 = 0x10;
        const RFU_2_3 = 0x20;
        const ATTESTED_CREDENTIALS = 0x40;
        const EXTENSION_DATA = 0x80;
    }
}

#[derive(Debug, Clone)]
pub struct AttestedCredentialData {
    pub aaguid: [u8; 16],
    pub credential_id: Vec<u8>,
    pub credential_public_key: PublicKey,
}

impl From<&AttestedCredentialData> for Ctap2PublicKeyCredentialDescriptor {
    fn from(data: &AttestedCredentialData) -> Self {
        Self {
            r#type: Ctap2PublicKeyCredentialType::PublicKey,
            id: ByteBuf::from(data.credential_id.clone()),
            transports: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticatorData<T> {
    pub rp_id_hash: [u8; 32],
    pub flags: AuthenticatorDataFlags,
    pub signature_count: u32,
    pub attested_credential: Option<AttestedCredentialData>,
    pub extensions: Option<T>,
}

impl<T> AuthenticatorData<T>
where
    T: Clone + Serialize,
{
    pub fn to_response_bytes(&self) -> Result<Vec<u8>, Error> {
        // Name                    | Length
        // -----------------------------------
        // rpIdHash                | 32
        // flags                   | 1
        // signCount               | 4
        // attestedCredentialData  | variable
        // extensions              | variable
        let mut res = self.rp_id_hash.to_vec();
        res.push(self.flags.bits());
        res.write_u32::<BigEndian>(self.signature_count)
            .map_err(|e| {
                error!("Failed to create AuthenticatorData output vec at signature_count: {e:?}");
                Error::Platform(PlatformError::InvalidDeviceResponse)
            })?;

        if let Some(att_data) = &self.attested_credential {
            // Name                 | Length
            // --------------------------------
            //  aaguid              | 16
            //  credentialIdLenght  | 2
            //  credentialId        | L
            //  credentialPublicKey | variable
            res.extend(att_data.aaguid);
            res.write_u16::<BigEndian>(att_data.credential_id.len() as u16)
            .map_err(|e| {
                error!(
                    "Failed to create AuthenticatorData output vec at attested_credential.credential_id: {e:?}"
                );
                Error::Platform(PlatformError::InvalidDeviceResponse)
            })?;
            res.extend(&att_data.credential_id);
            let cose_encoded_public_key =
                cbor::to_vec(&att_data.credential_public_key)
            .map_err(|e| {
                error!(
                    %e,
                    "Failed to create AuthenticatorData output vec at attested_credential.credential_public_key"  
                );
                Error::Platform(PlatformError::InvalidDeviceResponse)
            })?;
            res.extend(cose_encoded_public_key);
        }

        if self.extensions.is_some() || self.flags.contains(AuthenticatorDataFlags::EXTENSION_DATA)
        {
            res.extend(cbor::to_vec(&self.extensions).map_err(|e| {
                error!(%e, "Failed to create AuthenticatorData output vec at extensions");
                Error::Platform(PlatformError::InvalidDeviceResponse)
            })?);
        }
        Ok(res)
    }
}

impl<T> TryFrom<&AuthenticatorData<T>> for Ctap2PublicKeyCredentialDescriptor {
    type Error = CtapError;

    fn try_from(data: &AuthenticatorData<T>) -> Result<Self, Self::Error> {
        if let Some(att_data) = &data.attested_credential {
            Ok(att_data.into())
        } else {
            warn!("Failed to parse credential ID: invalid authenticator data length");
            Err(CtapError::InvalidCredential)
        }
    }
}

impl<'de, T: DeserializeOwned> Deserialize<'de> for AuthenticatorData<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // This is a bit ugly. The Visitor needs _something_ of type T (which is Deserialize),
        // for the compiler to grok this. So we have to add PhantomData of type T here, in
        // order for us to be able to specify "type Value = AuthenticatorData<T>"
        struct AuthenticatorDataVisitor<T>(PhantomData<T>);

        impl<'de, T: DeserializeOwned> Visitor<'de> for AuthenticatorDataVisitor<T> {
            type Value = AuthenticatorData<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("ByteBuf: Authenticator data")
            }

            fn visit_bytes<E>(self, data: &[u8]) -> Result<Self::Value, E>
            where
                E: DesError,
            {
                // Name                    | Length      | Start index
                // ---------------------------------------------------
                // rpIdHash                | 32          | 0
                // flags                   | 1           | 32
                // signCount               | 4           | 33
                // attestedCredentialData  | variable    |
                //     aaguid              |    16       | 37
                //     credentialIdLenght  |    2        | 53
                //     credentialId        |    L        | 55
                //     credentialPublicKey |    variable |
                // extensions              | variable    | variable

                // -> 32 + 1 + 4 = 37
                if data.len() < 37 {
                    return Err(DesError::invalid_length(data.len(), &"37"));
                }

                let mut cursor = Cursor::new(&data);
                let mut rp_id_hash = [0u8; 32];
                cursor.read_exact(&mut rp_id_hash).unwrap(); // We checked the length
                let flags_raw = cursor.read_u8().unwrap(); // We checked the length
                let flags = AuthenticatorDataFlags::from_bits_truncate(flags_raw);
                let signature_count = cursor.read_u32::<BigEndian>().unwrap(); // We checked the length

                let attested_credential =
                    if flags.contains(AuthenticatorDataFlags::ATTESTED_CREDENTIALS) {
                        // -> 32 + 1 + 4 + 16 + 2 + X = 55
                        if data.len() < 55 {
                            return Err(DesError::invalid_length(data.len(), &"55"));
                        }

                        let mut aaguid = [0u8; 16];
                        cursor.read_exact(&mut aaguid).unwrap(); // We checked the length
                        let credential_id_len = cursor.read_u16::<BigEndian>().unwrap() as usize; // We checked the length
                        if data.len() < 55 + credential_id_len {
                            return Err(DesError::invalid_length(data.len(), &"55+L"));
                        }
                        let mut credential_id = vec![0u8; credential_id_len];
                        cursor.read_exact(&mut credential_id).unwrap(); // We checked the length

                        let credential_public_key: PublicKey =
                            cbor::from_cursor(&mut cursor).map_err(DesError::custom)?;

                        Some(AttestedCredentialData {
                            aaguid,
                            credential_id,
                            credential_public_key,
                        })
                    } else {
                        Default::default()
                    };

                let extensions: Option<T> =
                    if flags.contains(AuthenticatorDataFlags::EXTENSION_DATA) {
                        cbor::from_cursor(&mut cursor).map_err(DesError::custom)?
                    } else {
                        Default::default()
                    };

                // Check if we have trailing data
                if !&data[cursor.position() as usize..].is_empty() {
                    return Err(DesError::invalid_length(data.len(), &"trailing data"));
                }

                Ok(AuthenticatorData {
                    rp_id_hash,
                    flags,
                    signature_count,
                    attested_credential,
                    extensions,
                })
            }
        }

        deserializer.deserialize_bytes(AuthenticatorDataVisitor(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use cosey::{Bytes, Ed25519PublicKey};
    use serde_bytes::ByteBuf;

    use crate::proto::ctap2::cbor;

    use super::{AttestedCredentialData, AuthenticatorData, AuthenticatorDataFlags};

    #[test]
    fn test_serialize_auth_data() {
        // SHA-256 'example.com'
        let rp_id_hash = [
            0xa3, 0x79, 0xa6, 0xf6, 0xee, 0xaf, 0xb9, 0xa5, 0x5e, 0x37, 0x8c, 0x11, 0x80, 0x34,
            0xe2, 0x75, 0x1e, 0x68, 0x2f, 0xab, 0x9f, 0x2d, 0x30, 0xab, 0x13, 0xd2, 0x12, 0x55,
            0x86, 0xce, 0x19, 0x47,
        ];
        let flag_bits = 0b1100_0101;
        let flags = AuthenticatorDataFlags::USER_PRESENT
            | AuthenticatorDataFlags::USER_VERIFIED
            | AuthenticatorDataFlags::ATTESTED_CREDENTIALS
            | AuthenticatorDataFlags::EXTENSION_DATA;
        assert_eq!(flag_bits, flags.bits());
        let signature_count = 0;
        let aaguid = [
            0x24, 0x38, 0x65, 0x2a, 0xbe, 0x9f, 0xbd, 0x84, 0x81, 0x0a, 0x84, 0x0d, 0x6f, 0xc4,
            0x42, 0xa8,
        ];
        let credential_id = vec![0x01, 0x01, 0x03, 0x03, 0x05, 0x05, 0x07, 0x07];
        let pub_key_bytes = b"]\"\xff\xc5\x932x(\xd6-:1\xbb}\x8c$7\xf1&\xd4\xb4&\x02\x02\xa3\xd9\xe2\xba1\x1f\xec\xba";
        let credential_public_key = cosey::PublicKey::Ed25519Key(Ed25519PublicKey {
            x: Bytes::from_slice(pub_key_bytes).unwrap(),
        });
        /*
         * A4                                      # map(4)
         *    01                                   # unsigned(1) kty
         *    01                                   # unsigned(1) OKP
         *    03                                   # unsigned(3) alg
         *    27                                   # negative(7) EdDSA
         *    20                                   # negative(0) crv
         *    06                                   # unsigned(6) Ed25519
         *    21                                   # negative(1) x
         *    58 20                                # bytes(32) [bytes, length 32]
         *       5D22FFC593327828D62D3A31BB7D8C2437F126D4B4260202A3D9E2BA311FECBA # "]\"\xFFœ2x(\xD6-:1\xBB}\x8C$7\xF1&Դ&\u0002\u0002\xA3\xD9\xE2\xBA1\u001F\xEC\xBA"
         */
        let mut cose_bytes = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20];
        cose_bytes.extend(pub_key_bytes);
        let attested_credential = AttestedCredentialData {
            aaguid,
            credential_id: credential_id.clone(),
            credential_public_key,
        };
        type T = String;
        let extensions: T = "test cbor serializable thing".to_string();

        let auth_data: AuthenticatorData<T> = AuthenticatorData {
            rp_id_hash,
            flags,
            signature_count,
            attested_credential: Some(attested_credential.clone()),
            extensions: Some(extensions.clone()),
        };
        let webauthn_auth_data = auth_data.to_response_bytes().unwrap();
        assert_eq!(rp_id_hash, &webauthn_auth_data[..32]);
        assert_eq!(flag_bits, webauthn_auth_data[32]);
        assert_eq!(
            u32::to_be_bytes(signature_count),
            webauthn_auth_data[33..37]
        );
        assert_eq!(aaguid, &webauthn_auth_data[37..37 + 16]);
        assert_eq!(
            &credential_id,
            &webauthn_auth_data[55..55 + &credential_id.len()]
        );
        let extensions_bytes = cbor::to_vec(&extensions).unwrap();
        assert_eq!(
            cose_bytes,
            &webauthn_auth_data
                [55 + credential_id.len()..webauthn_auth_data.len() - extensions_bytes.len()]
        );

        // Round-trip test: deserialize the serialized bytes and verify all fields match
        let authdata_wrapped = cbor::to_vec(&ByteBuf::from(webauthn_auth_data)).unwrap();
        let auth_data_reparsed: AuthenticatorData<T> =
            cbor::from_slice(authdata_wrapped.as_slice()).unwrap();
        assert_eq!(auth_data.rp_id_hash, auth_data_reparsed.rp_id_hash);
        assert_eq!(auth_data.flags.bits(), auth_data_reparsed.flags.bits());
        assert_eq!(
            auth_data.signature_count,
            auth_data_reparsed.signature_count
        );
        let attested_credential_reparsed = auth_data_reparsed.attested_credential.unwrap();
        assert_eq!(
            attested_credential.aaguid,
            attested_credential_reparsed.aaguid
        );
        assert_eq!(
            attested_credential.credential_id,
            attested_credential_reparsed.credential_id
        );
        assert_eq!(
            attested_credential.credential_public_key,
            attested_credential_reparsed.credential_public_key
        );
        assert_eq!(extensions, auth_data_reparsed.extensions.unwrap());
    }
}
