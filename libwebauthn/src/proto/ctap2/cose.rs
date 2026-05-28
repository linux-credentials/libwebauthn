//! Helpers for COSE_Key blobs carried opaquely on the CTAP wire.
//!
//! libwebauthn shuttles credential public keys between authenticator and
//! relying party as raw COSE bytes per [RFC 9052]. The platform layer only
//! needs to read the `alg` parameter (mandatory per WebAuthn L3 §6.5.2) so
//! it can populate `getPublicKeyAlgorithm()` and decide whether to build a
//! `SubjectPublicKeyInfo` in `getPublicKey()`. Everything else stays as
//! bytes for the RP to validate.
//!
//! [RFC 9052]: https://www.rfc-editor.org/rfc/rfc9052.html

use serde::{Deserialize, Deserializer};
use serde_cbor_2::Value;
use tracing::warn;

use crate::proto::ctap2::Ctap2COSEAlgorithmIdentifier;
use crate::webauthn::{Error, PlatformError};

/// COSE Key Common Parameter `alg`, label 3 ([RFC 9052] §7.1).
const COSE_KEY_LABEL_ALG: i128 = 3;

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

/// Read the `alg` parameter from a COSE_Key encoded as CBOR bytes.
///
/// Per WebAuthn L3 §6.5.2, every credential public key MUST include the
/// `alg` parameter. A missing, non-integer, or out-of-range value is
/// treated as an invalid device response.
pub(crate) fn read_alg(bytes: &[u8]) -> Result<Ctap2COSEAlgorithmIdentifier, Error> {
    let value: Value = serde_cbor_2::from_slice(bytes).map_err(|e| {
        warn!(%e, "failed to parse COSE_Key as CBOR");
        Error::Platform(PlatformError::InvalidDeviceResponse)
    })?;

    let Value::Map(map) = value else {
        warn!("COSE_Key is not a CBOR map");
        return Err(Error::Platform(PlatformError::InvalidDeviceResponse));
    };

    let alg_value = map
        .get(&Value::Integer(COSE_KEY_LABEL_ALG))
        .ok_or_else(|| {
            warn!("COSE_Key missing required `alg` parameter");
            Error::Platform(PlatformError::InvalidDeviceResponse)
        })?;

    let Value::Integer(alg) = alg_value else {
        warn!("COSE_Key `alg` is not an integer");
        return Err(Error::Platform(PlatformError::InvalidDeviceResponse));
    };

    let alg_i32 = i32::try_from(*alg).map_err(|_| {
        warn!(alg = %alg, "COSE_Key `alg` outside i32 range");
        Error::Platform(PlatformError::InvalidDeviceResponse)
    })?;

    Ok(Ctap2COSEAlgorithmIdentifier(alg_i32))
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
}
