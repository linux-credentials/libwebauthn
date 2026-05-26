//! Helpers for COSE_Key blobs carried opaquely on the CTAP wire.
//!
//! libwebauthn shuttles credential public keys between authenticator and
//! relying party as raw COSE bytes per [RFC 9052]. The platform layer only
//! needs to read the `alg` parameter (mandatory per WebAuthn L3 §6.5.2) so
//! it can populate `getPublicKeyAlgorithm()` and, for the algorithms it
//! understands, build a `SubjectPublicKeyInfo` for `getPublicKey()`.
//!
//! [RFC 9052]: https://www.rfc-editor.org/rfc/rfc9052.html

use der::asn1::{BitString, Null};
use der::{Decode, Encode, Sequence};
use serde::{Deserialize, Deserializer};
use serde_cbor_2::Value;
use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};
use tracing::warn;

use crate::proto::ctap2::Ctap2COSEAlgorithmIdentifier;
use crate::webauthn::{Error, PlatformError};

/// COSE Key Common Parameters ([RFC 9052] §7.1).
const COSE_KEY_LABEL_KTY: i128 = 1;
const COSE_KEY_LABEL_ALG: i128 = 3;

/// EC2 / OKP key parameters ([RFC 9053] §7.1, §7.2).
const COSE_KEY_LABEL_CRV: i128 = -1;
const COSE_KEY_LABEL_X: i128 = -2;
const COSE_KEY_LABEL_Y: i128 = -3;

/// RSA key parameters ([RFC 8230] §4).
const COSE_KEY_LABEL_N: i128 = -1;
const COSE_KEY_LABEL_E: i128 = -2;

const COSE_KTY_OKP: i128 = 1;
const COSE_KTY_EC2: i128 = 2;
const COSE_KTY_RSA: i128 = 3;

const COSE_CRV_P256: i128 = 1;
const COSE_CRV_ED25519: i128 = 6;

/// SPKI algorithm OIDs.
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// A COSE_Key captured opaquely as CBOR bytes.
///
/// The platform layer does not crypto-validate credential public keys, so
/// it stores them as bytes and forwards them to the RP. Use [`read_alg`]
/// to extract the algorithm identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoseEncodedKey(pub Vec<u8>);

impl CoseEncodedKey {
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for CoseEncodedKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let bytes = serde_cbor_2::to_vec(&value).map_err(serde::de::Error::custom)?;
        Ok(CoseEncodedKey(bytes))
    }
}

type CoseMap = std::collections::BTreeMap<Value, Value>;

fn parse_cose_map(bytes: &[u8]) -> Result<CoseMap, Error> {
    let value: Value = serde_cbor_2::from_slice(bytes).map_err(|e| {
        warn!(%e, "failed to parse COSE_Key as CBOR");
        Error::Platform(PlatformError::InvalidDeviceResponse)
    })?;
    match value {
        Value::Map(map) => Ok(map),
        _ => {
            warn!("COSE_Key is not a CBOR map");
            Err(Error::Platform(PlatformError::InvalidDeviceResponse))
        }
    }
}

fn map_integer(map: &CoseMap, label: i128) -> Result<i128, Error> {
    match map.get(&Value::Integer(label)) {
        Some(Value::Integer(i)) => Ok(*i),
        Some(_) => {
            warn!(label, "COSE_Key field is not an integer");
            Err(Error::Platform(PlatformError::InvalidDeviceResponse))
        }
        None => {
            warn!(label, "COSE_Key missing required field");
            Err(Error::Platform(PlatformError::InvalidDeviceResponse))
        }
    }
}

fn map_bytes(map: &CoseMap, label: i128) -> Result<&[u8], Error> {
    match map.get(&Value::Integer(label)) {
        Some(Value::Bytes(b)) => Ok(b.as_slice()),
        Some(_) => {
            warn!(label, "COSE_Key field is not a byte string");
            Err(Error::Platform(PlatformError::InvalidDeviceResponse))
        }
        None => {
            warn!(label, "COSE_Key missing required field");
            Err(Error::Platform(PlatformError::InvalidDeviceResponse))
        }
    }
}

fn read_alg_from_map(map: &CoseMap) -> Result<Ctap2COSEAlgorithmIdentifier, Error> {
    let alg_i128 = map_integer(map, COSE_KEY_LABEL_ALG)?;
    let alg_i32 = i32::try_from(alg_i128).map_err(|_| {
        warn!(alg = %alg_i128, "COSE_Key `alg` outside i32 range");
        Error::Platform(PlatformError::InvalidDeviceResponse)
    })?;
    Ok(Ctap2COSEAlgorithmIdentifier(alg_i32))
}

/// Read the `alg` parameter from a COSE_Key encoded as CBOR bytes.
///
/// Per WebAuthn L3 §6.5.2, every credential public key MUST include the
/// `alg` parameter. A missing, non-integer, or out-of-range value is
/// treated as an invalid device response.
pub(crate) fn read_alg(bytes: &[u8]) -> Result<Ctap2COSEAlgorithmIdentifier, Error> {
    let map = parse_cose_map(bytes)?;
    read_alg_from_map(&map)
}

/// Convert a COSE_Key to a DER-encoded `SubjectPublicKeyInfo`.
///
/// Returns:
/// - `Ok(Some(der))` for an understood algorithm with a well-formed key.
/// - `Ok(None)` when the algorithm is not in the supported set. This
///   matches WebAuthn L3 §5.2.1.1 which lets `getPublicKey()` return null
///   for algorithms the user agent does not implement.
/// - `Err(_)` when the algorithm IS understood but the COSE_Key is
///   malformed (missing fields, wrong shape, wrong curve, wrong sizes).
///
/// The supported set is the WebAuthn L3 floor (ES256, EdDSA, RS256) plus
/// ESP256 from RFC 9864, which maps to the same SPKI as ES256.
pub fn to_spki(bytes: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    let map = parse_cose_map(bytes)?;
    let alg = read_alg_from_map(&map)?;

    match alg {
        Ctap2COSEAlgorithmIdentifier::ES256 | Ctap2COSEAlgorithmIdentifier::ESP256 => {
            require_kty(&map, COSE_KTY_EC2)?;
            require_crv(&map, COSE_CRV_P256)?;
            let x = map_bytes(&map, COSE_KEY_LABEL_X)?;
            let y = map_bytes(&map, COSE_KEY_LABEL_Y)?;
            Ok(Some(p256_spki(x, y)?))
        }
        Ctap2COSEAlgorithmIdentifier::EDDSA => {
            require_kty(&map, COSE_KTY_OKP)?;
            require_crv(&map, COSE_CRV_ED25519)?;
            let x = map_bytes(&map, COSE_KEY_LABEL_X)?;
            Ok(Some(ed25519_spki(x)?))
        }
        Ctap2COSEAlgorithmIdentifier::RS256 => {
            require_kty(&map, COSE_KTY_RSA)?;
            let n = map_bytes(&map, COSE_KEY_LABEL_N)?;
            let e = map_bytes(&map, COSE_KEY_LABEL_E)?;
            Ok(Some(rs256_spki(n, e)?))
        }
        _ => Ok(None),
    }
}

fn require_kty(map: &CoseMap, expected: i128) -> Result<(), Error> {
    let kty = map_integer(map, COSE_KEY_LABEL_KTY)?;
    if kty != expected {
        warn!(expected, got = kty, "COSE_Key kty mismatch");
        return Err(Error::Platform(PlatformError::InvalidDeviceResponse));
    }
    Ok(())
}

fn require_crv(map: &CoseMap, expected: i128) -> Result<(), Error> {
    let crv = map_integer(map, COSE_KEY_LABEL_CRV)?;
    if crv != expected {
        warn!(expected, got = crv, "COSE_Key crv mismatch");
        return Err(Error::Platform(PlatformError::InvalidDeviceResponse));
    }
    Ok(())
}

fn p256_spki(x: &[u8], y: &[u8]) -> Result<Vec<u8>, Error> {
    if x.len() != 32 || y.len() != 32 {
        warn!(
            x_len = x.len(),
            y_len = y.len(),
            "P-256 coordinates wrong size"
        );
        return Err(Error::Platform(PlatformError::InvalidDeviceResponse));
    }
    let mut point = Vec::with_capacity(65);
    point.push(0x04); // uncompressed point indicator (SEC1)
    point.extend_from_slice(x);
    point.extend_from_slice(y);

    let curve_oid_der = OID_SECP256R1
        .to_der()
        .map_err(|_| Error::Platform(PlatformError::InvalidDeviceResponse))?;
    let parameters = der::Any::from_der(&curve_oid_der)
        .map_err(|_| Error::Platform(PlatformError::InvalidDeviceResponse))?;

    let spki = SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: OID_EC_PUBLIC_KEY,
            parameters: Some(parameters),
        },
        subject_public_key: BitString::from_bytes(&point)
            .map_err(|_| Error::Platform(PlatformError::InvalidDeviceResponse))?,
    };

    spki.to_der()
        .map_err(|_| Error::Platform(PlatformError::InvalidDeviceResponse))
}

fn ed25519_spki(x: &[u8]) -> Result<Vec<u8>, Error> {
    if x.len() != 32 {
        warn!(len = x.len(), "Ed25519 public key wrong size");
        return Err(Error::Platform(PlatformError::InvalidDeviceResponse));
    }

    let spki = SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: OID_ED25519,
            parameters: None,
        },
        subject_public_key: BitString::from_bytes(x)
            .map_err(|_| Error::Platform(PlatformError::InvalidDeviceResponse))?,
    };

    spki.to_der()
        .map_err(|_| Error::Platform(PlatformError::InvalidDeviceResponse))
}

#[derive(Sequence)]
struct Pkcs1RsaPublicKey<'a> {
    modulus: der::asn1::UintRef<'a>,
    public_exponent: der::asn1::UintRef<'a>,
}

fn rs256_spki(n: &[u8], e: &[u8]) -> Result<Vec<u8>, Error> {
    let inner = Pkcs1RsaPublicKey {
        modulus: der::asn1::UintRef::new(n)
            .map_err(|_| Error::Platform(PlatformError::InvalidDeviceResponse))?,
        public_exponent: der::asn1::UintRef::new(e)
            .map_err(|_| Error::Platform(PlatformError::InvalidDeviceResponse))?,
    };
    let inner_der = inner
        .to_der()
        .map_err(|_| Error::Platform(PlatformError::InvalidDeviceResponse))?;

    let null_der = Null
        .to_der()
        .map_err(|_| Error::Platform(PlatformError::InvalidDeviceResponse))?;
    let parameters = der::Any::from_der(&null_der)
        .map_err(|_| Error::Platform(PlatformError::InvalidDeviceResponse))?;

    let spki = SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: OID_RSA_ENCRYPTION,
            parameters: Some(parameters),
        },
        subject_public_key: BitString::from_bytes(&inner_der)
            .map_err(|_| Error::Platform(PlatformError::InvalidDeviceResponse))?,
    };

    spki.to_der()
        .map_err(|_| Error::Platform(PlatformError::InvalidDeviceResponse))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::ctap2::cbor;

    /// Minimal COSE_Key for ES256 P-256 (matches the canonical example in
    /// RFC 9053 §2.1).
    fn cose_key_es256() -> Vec<u8> {
        // {1: 2, 3: -7, -1: 1, -2: <32 bytes>, -3: <32 bytes>}
        cbor::to_vec(&serde_cbor_2::value::Value::Map(
            [
                (Value::Integer(1), Value::Integer(2)),
                (Value::Integer(3), Value::Integer(-7)),
                (Value::Integer(-1), Value::Integer(1)),
                (Value::Integer(-2), Value::Bytes(vec![0xAA; 32])),
                (Value::Integer(-3), Value::Bytes(vec![0xBB; 32])),
            ]
            .into_iter()
            .collect(),
        ))
        .unwrap()
    }

    /// Minimal COSE_Key for RS256 (RSA, kty=3, alg=-257, n, e).
    fn cose_key_rs256() -> Vec<u8> {
        cbor::to_vec(&Value::Map(
            [
                (Value::Integer(1), Value::Integer(3)),
                (Value::Integer(3), Value::Integer(-257)),
                (Value::Integer(-1), Value::Bytes(vec![0xCC; 256])),
                (Value::Integer(-2), Value::Bytes(vec![0x01, 0x00, 0x01])),
            ]
            .into_iter()
            .collect(),
        ))
        .unwrap()
    }

    /// Synthetic COSE_Key with a future / unrecognised `alg` value.
    fn cose_key_synthetic_pqc() -> Vec<u8> {
        cbor::to_vec(&Value::Map(
            [
                (Value::Integer(1), Value::Integer(7)),
                (Value::Integer(3), Value::Integer(-99999)),
                (Value::Integer(-1), Value::Bytes(vec![0xDD; 2592])),
            ]
            .into_iter()
            .collect(),
        ))
        .unwrap()
    }

    #[test]
    fn reads_es256_alg() {
        let alg = read_alg(&cose_key_es256()).unwrap();
        assert_eq!(alg, Ctap2COSEAlgorithmIdentifier::ES256);
        assert!(alg.is_known());
    }

    #[test]
    fn reads_rs256_alg() {
        let alg = read_alg(&cose_key_rs256()).unwrap();
        assert_eq!(alg, Ctap2COSEAlgorithmIdentifier::RS256);
        assert!(alg.is_known());
    }

    #[test]
    fn reads_unknown_alg_without_rewriting() {
        let alg = read_alg(&cose_key_synthetic_pqc()).unwrap();
        assert_eq!(alg, Ctap2COSEAlgorithmIdentifier(-99999));
        assert!(!alg.is_known());
    }

    #[test]
    fn rejects_missing_alg() {
        let bytes = cbor::to_vec(&Value::Map(
            [(Value::Integer(1), Value::Integer(2))]
                .into_iter()
                .collect(),
        ))
        .unwrap();
        assert!(read_alg(&bytes).is_err());
    }

    #[test]
    fn rejects_non_integer_alg() {
        let bytes = cbor::to_vec(&Value::Map(
            [(Value::Integer(3), Value::Text("ES256".into()))]
                .into_iter()
                .collect(),
        ))
        .unwrap();
        assert!(read_alg(&bytes).is_err());
    }

    #[test]
    fn rejects_non_map_root() {
        let bytes = cbor::to_vec(&Value::Integer(-7)).unwrap();
        assert!(read_alg(&bytes).is_err());
    }

    #[test]
    fn rejects_malformed_cbor() {
        assert!(read_alg(&[0xFF, 0xFF, 0xFF]).is_err());
    }

    fn cose_key_ed25519() -> Vec<u8> {
        cbor::to_vec(&Value::Map(
            [
                (Value::Integer(1), Value::Integer(COSE_KTY_OKP)),
                (Value::Integer(3), Value::Integer(-8)),
                (Value::Integer(-1), Value::Integer(COSE_CRV_ED25519)),
                (Value::Integer(-2), Value::Bytes(vec![0x11; 32])),
            ]
            .into_iter()
            .collect(),
        ))
        .unwrap()
    }

    fn cose_key_esp256() -> Vec<u8> {
        cbor::to_vec(&Value::Map(
            [
                (Value::Integer(1), Value::Integer(COSE_KTY_EC2)),
                (Value::Integer(3), Value::Integer(-9)),
                (Value::Integer(-1), Value::Integer(COSE_CRV_P256)),
                (Value::Integer(-2), Value::Bytes(vec![0x22; 32])),
                (Value::Integer(-3), Value::Bytes(vec![0x33; 32])),
            ]
            .into_iter()
            .collect(),
        ))
        .unwrap()
    }

    /// Re-parse the SPKI we just emitted and check the algorithm and inner
    /// key bytes match the input.
    fn parse_spki(der: &[u8]) -> spki::SubjectPublicKeyInfo<der::Any, BitString> {
        spki::SubjectPublicKeyInfo::from_der(der).unwrap()
    }

    #[test]
    fn emits_es256_spki() {
        let der = to_spki(&cose_key_es256()).unwrap().unwrap();
        let spki = parse_spki(&der);
        assert_eq!(spki.algorithm.oid, OID_EC_PUBLIC_KEY);
        let params_oid: ObjectIdentifier = der::asn1::ObjectIdentifier::from_der(
            &spki.algorithm.parameters.unwrap().to_der().unwrap(),
        )
        .unwrap();
        assert_eq!(params_oid, OID_SECP256R1);
        // 0x04 || X(32) || Y(32) = 65 bytes
        let key_bytes = spki.subject_public_key.raw_bytes();
        assert_eq!(key_bytes.len(), 65);
        assert_eq!(key_bytes[0], 0x04);
        assert_eq!(&key_bytes[1..33], &[0xAA; 32]);
        assert_eq!(&key_bytes[33..65], &[0xBB; 32]);
    }

    #[test]
    fn emits_same_spki_for_esp256_as_es256() {
        let es256_der = to_spki(&cose_key_es256()).unwrap().unwrap();
        let esp256_der = to_spki(&cose_key_esp256()).unwrap().unwrap();
        let es256_spki = parse_spki(&es256_der);
        let esp256_spki = parse_spki(&esp256_der);
        // Algorithm and parameter encoding are identical between ES256 and
        // ESP256 SPKI (both id-ecPublicKey + secp256r1), so the only diff
        // is the coordinate bytes themselves.
        assert_eq!(es256_spki.algorithm.oid, esp256_spki.algorithm.oid);
        assert_eq!(
            es256_spki.algorithm.parameters.unwrap().to_der().unwrap(),
            esp256_spki.algorithm.parameters.unwrap().to_der().unwrap()
        );
    }

    #[test]
    fn emits_ed25519_spki() {
        let der = to_spki(&cose_key_ed25519()).unwrap().unwrap();
        let spki = parse_spki(&der);
        assert_eq!(spki.algorithm.oid, OID_ED25519);
        assert!(spki.algorithm.parameters.is_none());
        let key_bytes = spki.subject_public_key.raw_bytes();
        assert_eq!(key_bytes.len(), 32);
        assert_eq!(key_bytes, &[0x11; 32]);
    }

    #[test]
    fn emits_rs256_spki() {
        let der = to_spki(&cose_key_rs256()).unwrap().unwrap();
        let spki = parse_spki(&der);
        assert_eq!(spki.algorithm.oid, OID_RSA_ENCRYPTION);
        let params = spki.algorithm.parameters.unwrap();
        // RSA SPKI per PKCS#1 §A.1: parameters MUST be NULL.
        Null::from_der(&params.to_der().unwrap()).unwrap();
        // Inner BIT STRING is a SEQUENCE of two INTEGERs (modulus, e).
        let inner = spki.subject_public_key.raw_bytes();
        let parsed: Pkcs1RsaPublicKey = Pkcs1RsaPublicKey::from_der(inner).unwrap();
        assert_eq!(parsed.modulus.as_bytes(), &[0xCC; 256]);
        assert_eq!(parsed.public_exponent.as_bytes(), &[0x01, 0x00, 0x01]);
    }

    #[test]
    fn returns_none_for_unknown_algorithm() {
        let bytes = cose_key_synthetic_pqc();
        assert!(matches!(to_spki(&bytes), Ok(None)));
    }

    #[test]
    fn rejects_es256_with_wrong_curve() {
        let bytes = cbor::to_vec(&Value::Map(
            [
                (Value::Integer(1), Value::Integer(COSE_KTY_EC2)),
                (Value::Integer(3), Value::Integer(-7)),
                (Value::Integer(-1), Value::Integer(2)), // P-384, not P-256
                (Value::Integer(-2), Value::Bytes(vec![0xAA; 48])),
                (Value::Integer(-3), Value::Bytes(vec![0xBB; 48])),
            ]
            .into_iter()
            .collect(),
        ))
        .unwrap();
        assert!(to_spki(&bytes).is_err());
    }

    #[test]
    fn rejects_es256_with_short_coordinate() {
        let bytes = cbor::to_vec(&Value::Map(
            [
                (Value::Integer(1), Value::Integer(COSE_KTY_EC2)),
                (Value::Integer(3), Value::Integer(-7)),
                (Value::Integer(-1), Value::Integer(COSE_CRV_P256)),
                (Value::Integer(-2), Value::Bytes(vec![0xAA; 16])), // short
                (Value::Integer(-3), Value::Bytes(vec![0xBB; 32])),
            ]
            .into_iter()
            .collect(),
        ))
        .unwrap();
        assert!(to_spki(&bytes).is_err());
    }

    #[test]
    fn rejects_rs256_missing_modulus() {
        let bytes = cbor::to_vec(&Value::Map(
            [
                (Value::Integer(1), Value::Integer(COSE_KTY_RSA)),
                (Value::Integer(3), Value::Integer(-257)),
                (Value::Integer(-2), Value::Bytes(vec![0x01, 0x00, 0x01])),
            ]
            .into_iter()
            .collect(),
        ))
        .unwrap();
        assert!(to_spki(&bytes).is_err());
    }

    #[test]
    fn rejects_eddsa_with_wrong_kty() {
        let bytes = cbor::to_vec(&Value::Map(
            [
                (Value::Integer(1), Value::Integer(COSE_KTY_EC2)), // wrong
                (Value::Integer(3), Value::Integer(-8)),
                (Value::Integer(-1), Value::Integer(COSE_CRV_ED25519)),
                (Value::Integer(-2), Value::Bytes(vec![0x11; 32])),
            ]
            .into_iter()
            .collect(),
        ))
        .unwrap();
        assert!(to_spki(&bytes).is_err());
    }
}
