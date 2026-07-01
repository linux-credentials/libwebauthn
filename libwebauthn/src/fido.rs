//! Protocol abstractions shared between FIDO2 (CTAP2) and FIDO U2F (CTAP1).
//! This module models the common protocol surface of the two standards,
//! including protocol negotiation via [`FidoProtocol`], revision tracking via
//! [`FidoRevision`], and the [`AuthenticatorData`] structure returned by a
//! device during authentication and attestation ceremonies.
//!
//! [`AuthenticatorData`] is the central type. It carries the relying party ID
//! hash, the user presence and verification flags, the signature counter,
//! optional attested credential data (the device AAGUID, credential ID, and
//! credential public key), and any protocol extension outputs. The module
//! serializes and deserializes these responses per the CTAP2 specification and
//! preserves the COSE key bytes verbatim, so the device signatures a relying
//! party verifies stay intact.

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
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
    webauthn::PlatformError,
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
        const BACKUP_ELIGIBILITY = 0x08;
        const BACKUP_STATE = 0x10;
        const RFU_2_3 = 0x20;
        const ATTESTED_CREDENTIALS = 0x40;
        const EXTENSION_DATA = 0x80;
    }
}

#[derive(Debug, Clone)]
pub struct AttestedCredentialData {
    pub aaguid: [u8; 16],
    pub credential_id: Vec<u8>,
    /// Credential public key in COSE_Key CBOR encoding (RFC 9052).
    ///
    /// Stored verbatim so the authenticator data signature over it
    /// remains valid for relying-party verification. The platform does
    /// not crypto-validate this key.
    pub credential_public_key: Vec<u8>,
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
    /// Raw authData bytes as received from the device, preserved verbatim so
    /// the RP's signature over authData stays valid. `None` for authData the
    /// platform synthesizes (e.g. the U2F upgrade path), which is rebuilt from
    /// the fields above.
    pub raw: Option<Vec<u8>>,
}

impl<T> AuthenticatorData<T> {
    /// Backup Eligibility (BE): the credential may be backed up or synced.
    pub fn backup_eligible(&self) -> bool {
        self.flags
            .contains(AuthenticatorDataFlags::BACKUP_ELIGIBILITY)
    }

    /// Backup State (BS): the credential is currently backed up.
    pub fn backed_up(&self) -> bool {
        self.flags.contains(AuthenticatorDataFlags::BACKUP_STATE)
    }
}

impl<T> AuthenticatorData<T>
where
    T: Clone + Serialize,
{
    pub fn to_response_bytes(&self) -> Result<Vec<u8>, PlatformError> {
        // Return the device's authData verbatim. Re-encoding from the parsed
        // fields would reorder or drop unmodeled extensions, invalidating the
        // authenticator's signature over these exact bytes.
        if let Some(raw) = &self.raw {
            return Ok(raw.clone());
        }
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
                PlatformError::InvalidDeviceResponse
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
                PlatformError::InvalidDeviceResponse
            })?;
            res.extend(&att_data.credential_id);
            res.extend(&att_data.credential_public_key);
        }

        if self.extensions.is_some() || self.flags.contains(AuthenticatorDataFlags::EXTENSION_DATA)
        {
            res.extend(cbor::to_vec(&self.extensions).map_err(|e| {
                error!(%e, "Failed to create AuthenticatorData output vec at extensions");
                PlatformError::InvalidDeviceResponse
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
                cursor
                    .read_exact(&mut rp_id_hash)
                    .map_err(|e| DesError::custom(format!("failed to read rp_id_hash: {e}")))?;
                let flags_raw = cursor
                    .read_u8()
                    .map_err(|e| DesError::custom(format!("failed to read flags: {e}")))?;
                let flags = AuthenticatorDataFlags::from_bits_truncate(flags_raw);
                let signature_count = cursor.read_u32::<BigEndian>().map_err(|e| {
                    DesError::custom(format!("failed to read signature_count: {e}"))
                })?;

                let attested_credential =
                    if flags.contains(AuthenticatorDataFlags::ATTESTED_CREDENTIALS) {
                        // -> 32 + 1 + 4 + 16 + 2 + X = 55
                        if data.len() < 55 {
                            return Err(DesError::invalid_length(data.len(), &"55"));
                        }

                        let mut aaguid = [0u8; 16];
                        cursor
                            .read_exact(&mut aaguid)
                            .map_err(|e| DesError::custom(format!("failed to read aaguid: {e}")))?;
                        let credential_id_len = cursor.read_u16::<BigEndian>().map_err(|e| {
                            DesError::custom(format!("failed to read credential_id_len: {e}"))
                        })? as usize;
                        if data.len() < 55 + credential_id_len {
                            return Err(DesError::invalid_length(data.len(), &"55+L"));
                        }
                        let mut credential_id = vec![0u8; credential_id_len];
                        cursor.read_exact(&mut credential_id).map_err(|e| {
                            DesError::custom(format!("failed to read credential_id: {e}"))
                        })?;

                        // Capture the COSE_Key bytes verbatim so the RP's
                        // signature check over authData stays valid. Parse
                        // through cbor::Value only to advance the cursor by
                        // exactly one CBOR item.
                        let cose_start = cursor.position() as usize;
                        let _: cbor::Value =
                            cbor::from_cursor(&mut cursor).map_err(DesError::custom)?;
                        let cose_end = cursor.position() as usize;
                        let credential_public_key = data
                            .get(cose_start..cose_end)
                            .ok_or_else(|| {
                                DesError::custom("cursor reported COSE_Key span outside authData")
                            })?
                            .to_vec();

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
                let pos = cursor.position() as usize;
                let trailing = data.get(pos..).ok_or_else(|| {
                    DesError::custom("cursor advanced past end of authenticator data")
                })?;
                if !trailing.is_empty() {
                    return Err(DesError::invalid_length(data.len(), &"trailing data"));
                }

                Ok(AuthenticatorData {
                    rp_id_hash,
                    flags,
                    signature_count,
                    attested_credential,
                    extensions,
                    raw: Some(data.to_vec()),
                })
            }
        }

        deserializer.deserialize_bytes(AuthenticatorDataVisitor(PhantomData))
    }
}

#[cfg(test)]
mod tests {
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
        let flag_bits = 0b1101_1101;
        let flags = AuthenticatorDataFlags::USER_PRESENT
            | AuthenticatorDataFlags::USER_VERIFIED
            | AuthenticatorDataFlags::BACKUP_ELIGIBILITY
            | AuthenticatorDataFlags::BACKUP_STATE
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
            credential_public_key: cose_bytes.clone(),
        };
        type T = String;
        let extensions: T = "test cbor serializable thing".to_string();

        let auth_data: AuthenticatorData<T> = AuthenticatorData {
            rp_id_hash,
            flags,
            signature_count,
            attested_credential: Some(attested_credential.clone()),
            extensions: Some(extensions.clone()),
            raw: None,
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
        assert!(auth_data_reparsed
            .flags
            .contains(AuthenticatorDataFlags::BACKUP_ELIGIBILITY));
        assert!(auth_data_reparsed
            .flags
            .contains(AuthenticatorDataFlags::BACKUP_STATE));
        assert!(auth_data_reparsed.backup_eligible());
        assert!(auth_data_reparsed.backed_up());
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

    #[test]
    fn auth_data_parses_with_non_p256_credential_public_key() {
        // Build a synthetic COSE_Key for RS256 (kty=3 RSA, alg=-257, n, e).
        // Previous versions of libwebauthn couldn't parse authData carrying
        // anything other than P-256 or Ed25519 because cosey::PublicKey is
        // a closed enum. With opaque byte storage this now round-trips.
        use crate::proto::ctap2::cose;
        use serde_cbor_2::Value;

        let rsa_cose = cbor::to_vec(&Value::Map(
            [
                (Value::Integer(1), Value::Integer(3)),
                (Value::Integer(3), Value::Integer(-257)),
                (Value::Integer(-1), Value::Bytes(vec![0xAA; 256])),
                (Value::Integer(-2), Value::Bytes(vec![0x01, 0x00, 0x01])),
            ]
            .into_iter()
            .collect(),
        ))
        .unwrap();

        let rp_id_hash = [0x77u8; 32];
        let aaguid = [0x42u8; 16];
        let credential_id = vec![0xC1, 0xC2, 0xC3];
        let attested_credential = AttestedCredentialData {
            aaguid,
            credential_id: credential_id.clone(),
            credential_public_key: rsa_cose.clone(),
        };
        type T = String;
        let auth_data: AuthenticatorData<T> = AuthenticatorData {
            rp_id_hash,
            flags: AuthenticatorDataFlags::USER_PRESENT
                | AuthenticatorDataFlags::ATTESTED_CREDENTIALS,
            signature_count: 1,
            attested_credential: Some(attested_credential),
            extensions: None,
            raw: None,
        };

        let bytes = auth_data.to_response_bytes().unwrap();
        let wrapped = cbor::to_vec(&ByteBuf::from(bytes)).unwrap();
        let parsed: AuthenticatorData<T> = cbor::from_slice(&wrapped).unwrap();

        let credential = parsed.attested_credential.expect("AT flag was set");
        assert_eq!(credential.credential_public_key, rsa_cose);
        assert_eq!(
            cose::read_alg(&credential.credential_public_key).unwrap(),
            crate::proto::ctap2::Ctap2COSEAlgorithmIdentifier::RS256
        );
    }

    #[test]
    fn to_response_bytes_preserves_extensions_verbatim() {
        // The authenticator signs over the exact authData bytes, including the
        // extensions block. Re-encoding from the typed struct drops keys it does
        // not model (and may reorder the rest), which would break relying-party
        // signature verification. The bytes must round-trip unchanged.
        use crate::proto::ctap2::Ctap2MakeCredentialsResponseExtensions;

        let flags = AuthenticatorDataFlags::USER_PRESENT
            | AuthenticatorDataFlags::BACKUP_ELIGIBILITY
            | AuthenticatorDataFlags::BACKUP_STATE
            | AuthenticatorDataFlags::EXTENSION_DATA;
        let mut input = [0x11u8; 32].to_vec();
        input.push(flags.bits());
        input.extend_from_slice(&[0x00, 0x00, 0x00, 0x07]); // signCount

        // CBOR: { "credBlob": true, "thirdPartyPayment": true }. The second key
        // is unmodeled, so the typed struct drops it on re-encode.
        input.extend_from_slice(&[
            0xA2, // map(2)
            0x68, b'c', b'r', b'e', b'd', b'B', b'l', b'o', b'b', 0xF5, // "credBlob": true
            0x71, b't', b'h', b'i', b'r', b'd', b'P', b'a', b'r', b't', b'y', b'P', b'a', b'y',
            b'm', b'e', b'n', b't', 0xF5, // "thirdPartyPayment": true
        ]);

        let wrapped = cbor::to_vec(&ByteBuf::from(input.clone())).unwrap();
        let parsed: AuthenticatorData<Ctap2MakeCredentialsResponseExtensions> =
            cbor::from_slice(&wrapped).unwrap();

        assert!(parsed.backup_eligible());
        assert!(parsed.backed_up());

        assert_eq!(
            parsed.to_response_bytes().unwrap(),
            input,
            "authenticatorData must be preserved byte-for-byte"
        );
    }

    #[test]
    fn backup_flags_are_distinct_bits() {
        // BE and BS are separate bits per WebAuthn L3 section 6.1. Each accessor
        // must read its own bit, so a swap or a wrong wiring is caught.
        assert_eq!(AuthenticatorDataFlags::BACKUP_ELIGIBILITY.bits(), 0x08);
        assert_eq!(AuthenticatorDataFlags::BACKUP_STATE.bits(), 0x10);

        let with_flags = |flags| AuthenticatorData::<()> {
            rp_id_hash: [0u8; 32],
            flags,
            signature_count: 0,
            attested_credential: None,
            extensions: None,
            raw: None,
        };

        let be_only = with_flags(AuthenticatorDataFlags::BACKUP_ELIGIBILITY);
        assert!(be_only.backup_eligible());
        assert!(!be_only.backed_up());

        let bs_only = with_flags(AuthenticatorDataFlags::BACKUP_STATE);
        assert!(!bs_only.backup_eligible());
        assert!(bs_only.backed_up());
    }
}
