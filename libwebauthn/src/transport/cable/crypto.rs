use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use aes::{Aes256, Block};
use hkdf::Hkdf;
use sha2::Sha256;
use tracing::{instrument, warn};

use crate::pin::hmac_sha256;
use crate::transport::error::TransportError;
use crate::webauthn::error::Error;

pub enum KeyPurpose {
    EIDKey = 1,
    TunnelID = 2,
    Psk = 3,
}

pub fn derive(secret: &[u8], salt: Option<&[u8]>, purpose: KeyPurpose) -> Result<[u8; 64], Error> {
    let purpose32 = [purpose as u8, 0, 0, 0];

    let hkdf = Hkdf::<Sha256>::new(salt, secret);
    let mut output = [0u8; 64];
    hkdf.expand(&purpose32, &mut output)
        .map_err(|_| Error::Transport(TransportError::InvalidKey))?;
    Ok(output)
}

fn reserved_bits_are_zero(plaintext: &[u8]) -> bool {
    plaintext.first().copied() == Some(0)
}

#[instrument]
pub fn trial_decrypt_advert(eid_key: &[u8], candidate_advert: &[u8]) -> Option<[u8; 16]> {
    // Only the first 20 bytes are the encrypted advert; any remainder is the
    // advertisement suffix and is parsed separately by the caller.
    let Some(advert) = candidate_advert.get(..20) else {
        warn!("candidate advert is shorter than 20 bytes");
        return None;
    };

    if eid_key.len() != 64 {
        warn!("EID key is not 64 bytes");
        return None;
    }

    let mac_key = eid_key.get(32..)?;
    let advert_body = advert.get(..16)?;
    let advert_tag = advert.get(16..)?;
    let expected_tag = hmac_sha256(mac_key, advert_body).ok()?;
    let expected_tag_truncated = expected_tag.get(..4)?;
    if expected_tag_truncated != advert_tag {
        warn!({ expected = ?expected_tag_truncated, actual = ?advert_tag },
              "candidate advert HMAC tag does not match");
        return None;
    }

    let aes_key = eid_key.get(..32)?;
    let cipher = Aes256::new(GenericArray::from_slice(aes_key));
    let mut block = Block::clone_from_slice(advert_body);
    cipher.decrypt_block(&mut block);

    if !reserved_bits_are_zero(&block) {
        warn!("reserved bits are not zero");
        return None;
    }

    let mut plaintext = [0u8; 16];
    plaintext.copy_from_slice(&block);
    Some(plaintext)
}

#[cfg(test)]
mod tests {
    use super::derive;
    use super::trial_decrypt_advert;
    use super::KeyPurpose;
    use crate::pin::hmac_sha256;
    use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
    use aes::{Aes256, Block};

    /// Builds a self-consistent (eid_key, 20-byte advert) pair for a given plaintext.
    fn make_advert(plaintext: [u8; 16]) -> ([u8; 64], [u8; 20]) {
        let mut eid_key = [0u8; 64];
        for (i, b) in eid_key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let (aes_key, mac_key) = eid_key.split_at(32);

        let cipher = Aes256::new(GenericArray::from_slice(aes_key));
        let mut block = Block::clone_from_slice(&plaintext);
        cipher.encrypt_block(&mut block);

        let tag = hmac_sha256(mac_key, &block).unwrap();
        let mut advert = [0u8; 20];
        let (body, tail) = advert.split_at_mut(16);
        body.copy_from_slice(&block);
        tail.copy_from_slice(tag.get(..4).unwrap());
        (eid_key, advert)
    }

    #[test]
    fn trial_decrypt_advert_accepts_exactly_20_bytes() {
        let plaintext = [0u8; 16];
        let (eid_key, advert) = make_advert(plaintext);
        assert_eq!(trial_decrypt_advert(&eid_key, &advert), Some(plaintext));
    }

    #[test]
    fn trial_decrypt_advert_ignores_suffix() {
        let plaintext = [0u8; 16];
        let (eid_key, advert) = make_advert(plaintext);

        let mut with_suffix = advert.to_vec();
        with_suffix.extend_from_slice(&[0xA1, 0x01, 0x19, 0x12, 0x34]);

        assert_eq!(
            trial_decrypt_advert(&eid_key, &with_suffix),
            trial_decrypt_advert(&eid_key, &advert),
        );
        assert_eq!(
            trial_decrypt_advert(&eid_key, &with_suffix),
            Some(plaintext)
        );
    }

    #[test]
    fn trial_decrypt_advert_rejects_short_input() {
        let (eid_key, advert) = make_advert([0u8; 16]);
        assert_eq!(
            trial_decrypt_advert(&eid_key, advert.get(..19).unwrap()),
            None
        );
        assert_eq!(trial_decrypt_advert(&eid_key, &[]), None);
    }

    #[test]
    fn trial_decrypt_advert_rejects_bad_tag() {
        let (eid_key, mut advert) = make_advert([0u8; 16]);
        if let Some(b) = advert.last_mut() {
            *b ^= 0xFF;
        }
        assert_eq!(trial_decrypt_advert(&eid_key, &advert), None);
    }

    #[test]
    fn derive_eidkey_nosalt() {
        let input: [u8; 16] = hex::decode("00112233445566778899aabbccddeeff")
            .unwrap()
            .try_into()
            .unwrap();
        let output = derive(&input, None, KeyPurpose::EIDKey).unwrap().to_vec();
        let expected = hex::decode("efafab5b2c84a11c80e3ad0770353138b414a859ccd3afcc99e3d3250dba65084ede8e38e75432617c0ccae1ffe5d8143df0db0cd6d296f489419cd6411ee505").unwrap();
        assert_eq!(output, expected);
    }

    #[test]
    fn derive_eidkey_salt() {
        let input: [u8; 16] = hex::decode("00112233445566778899aabbccddeeff")
            .unwrap()
            .try_into()
            .unwrap();
        let salt = hex::decode("ffeeddccbbaa998877665544332211").unwrap();
        let output = derive(&input, Some(&salt), KeyPurpose::EIDKey)
            .unwrap()
            .to_vec();
        let expected = hex::decode("168cf3dd220a7907f8bac30f559be92a3b6d937fe5594beeaf1e50e35976b7d654dd550e22ae4c801b9d1cdbf0d2b1472daa1328661eb889acae3023b7ffa509").unwrap();
        assert_eq!(output, expected);
    }
}
