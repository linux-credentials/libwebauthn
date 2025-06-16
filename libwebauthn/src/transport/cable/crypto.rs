use aes::cipher::{BlockDecrypt, KeyInit};
use aes::{Aes256, Block};
use hkdf::Hkdf;
use sha2::Sha256;
use tracing::{instrument, warn};

use crate::pin::hmac_sha256;

pub enum KeyPurpose {
    EIDKey = 1,
    TunnelID = 2,
    PSK = 3,
}

pub fn derive(secret: &[u8], salt: Option<&[u8]>, purpose: KeyPurpose) -> [u8; 64] {
    let mut purpose32 = [0u8; 4];
    purpose32[0] = purpose as u8;

    let hkdf = Hkdf::<Sha256>::new(salt, secret);
    let mut output = [0u8; 64];
    hkdf.expand(&purpose32, &mut output).unwrap();
    output
}

fn reserved_bits_are_zero(plaintext: &[u8]) -> bool {
    plaintext[0] == 0
}

#[instrument]
pub fn trial_decrypt_advert(eid_key: &[u8], candidate_advert: &[u8]) -> Option<[u8; 16]> {
    if candidate_advert.len() != 20 {
        warn!("candidate advert is not 20 bytes");
        return None;
    }

    if eid_key.len() != 64 {
        warn!("EID key is not 64 bytes");
        return None;
    }

    let expected_tag = hmac_sha256(&eid_key[32..], &candidate_advert[..16]);
    if expected_tag[..4] != candidate_advert[16..] {
        warn!({ expected = ?expected_tag[..4], actual = ?candidate_advert[16..] },
              "candidate advert HMAC tag does not match");
        return None;
    }

    let cipher = Aes256::new_from_slice(&eid_key[..32]).unwrap();
    let mut block = Block::clone_from_slice(&candidate_advert[..16]);
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
    use super::KeyPurpose;

    #[test]
    fn derive_eidkey_nosalt() {
        let input: [u8; 16] = hex::decode("00112233445566778899aabbccddeeff")
            .unwrap()
            .try_into()
            .unwrap();
        let output = derive(&input, None, KeyPurpose::EIDKey).to_vec();
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
        let output = derive(&input, Some(&salt), KeyPurpose::EIDKey).to_vec();
        let expected = hex::decode("168cf3dd220a7907f8bac30f559be92a3b6d937fe5594beeaf1e50e35976b7d654dd550e22ae4c801b9d1cdbf0d2b1472daa1328661eb889acae3023b7ffa509").unwrap();
        assert_eq!(output, expected);
    }
}
