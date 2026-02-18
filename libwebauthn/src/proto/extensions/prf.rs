use crate::ops::webauthn::{HMACGetSecretInput, PRFValue};

use cosey::PublicKey;
use serde_bytes::ByteBuf;
use serde_indexed::SerializeIndexed;
use sha2::{Digest, Sha256};

/// Converts a PRFValue to HMACGetSecretInput by hashing the PRF values with the
/// "WebAuthn PRF" prefix as specified in the WebAuthn PRF extension.
/// https://w3c.github.io/webauthn/#prf
///
/// Shared between GetAssertion (hmac-secret) and MakeCredential (hmac-secret-mc).
pub(crate) fn prf_value_to_hmac_input(ev: &PRFValue) -> HMACGetSecretInput {
    // SHA-256(UTF8Encode("WebAuthn PRF") || 0x00 || ev.first).
    let mut prefix = String::from("WebAuthn PRF").into_bytes();
    prefix.push(0x00);

    let mut input = HMACGetSecretInput::default();
    // 5.1 Let salt1 be the value of SHA-256(UTF8Encode("WebAuthn PRF") || 0x00 || ev.first).
    let mut salt1_input = prefix.clone();
    salt1_input.extend(ev.first);

    let mut hasher = Sha256::default();
    hasher.update(salt1_input);
    let salt1_hash = hasher.finalize().to_vec();
    input.salt1.copy_from_slice(&salt1_hash[..32]);

    // 5.2 If ev.second is present, let salt2 be the value of SHA-256(UTF8Encode("WebAuthn PRF") || 0x00 || ev.second).
    if let Some(second) = ev.second {
        let mut salt2_input = prefix.clone();
        salt2_input.extend(second);
        let mut hasher = Sha256::default();
        hasher.update(salt2_input);
        let salt2_hash = hasher.finalize().to_vec();
        let mut salt2 = [0u8; 32];
        salt2.copy_from_slice(&salt2_hash[..32]);
        input.salt2 = Some(salt2);
    };

    input
}

#[derive(Debug, Clone, SerializeIndexed)]
pub struct CalculatedHMACGetSecretInput {
    // keyAgreement(0x01): public key of platform key-agreement key.
    #[serde(index = 0x01)]
    pub public_key: PublicKey,
    // saltEnc(0x02): Encryption of the one or two salts
    #[serde(index = 0x02)]
    pub salt_enc: ByteBuf,
    // saltAuth(0x03): authenticate(shared secret, saltEnc)
    #[serde(index = 0x03)]
    pub salt_auth: ByteBuf,
    // pinUvAuthProtocol(0x04): (optional) as selected when getting the shared secret. CTAP2.1 platforms MUST include this parameter if the value of pinUvAuthProtocol is not 1.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x04)]
    pub pin_auth_proto: Option<u32>,
}
