use std::time::Duration;

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut};
use async_trait::async_trait;
use cbc::cipher::{BlockEncryptMut, KeyIvInit};
use cosey as cose;
use hkdf::Hkdf;
use hmac::Mac;
use p256::{
    ecdh::EphemeralSecret, elliptic_curve::sec1::FromEncodedPoint, EncodedPoint,
    PublicKey as P256PublicKey,
};
use rand::{rngs::OsRng, thread_rng, Rng};
use sha2::{Digest, Sha256};
use tracing::{error, instrument, warn};
use x509_parser::nom::AsBytes;

use crate::{
    proto::{
        ctap2::{Ctap2, Ctap2ClientPinRequest, Ctap2PinUvAuthProtocol},
        CtapError,
    },
    transport::Channel,
    webauthn::{
        error::{Error, PlatformError},
        obtain_pin, obtain_shared_secret, select_uv_proto,
    },
};

type Aes256CbcEncryptor = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDecryptor = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = hmac::Hmac<Sha256>;

#[derive(Default, Debug)]
pub struct PinUvAuthToken {
    pub rpid: Option<String>,
    pub user_verified: bool,
    pub user_present: bool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PinRequestReason {
    /// The RP required a PIN
    RelyingPartyRequest,
    /// The device is configured to require a PIN
    AuthenticatorPolicy,
    /// Buitin UV failed and is temporarily blocked, and we have to enter a valid PIN to unblock it
    FallbackFromUV,
    // Passkey
}

pub trait PinUvAuthProtocol: Send + Sync {
    fn version(&self) -> Ctap2PinUvAuthProtocol;

    /// encapsulate(peerCoseKey) → (coseKey, sharedSecret) | error
    ///   Generates an encapsulation for the authenticator’s public key and returns the message to transmit and the
    ///   shared secret.
    fn encapsulate(
        &self,
        peer_public_key: &cose::PublicKey,
    ) -> Result<(cose::PublicKey, Vec<u8>), Error>;

    // encrypt(key, demPlaintext) → ciphertext
    //   Encrypts a plaintext to produce a ciphertext, which may be longer than the plaintext.
    //   The plaintext is restricted to being a multiple of the AES block size (16 bytes) in length.
    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error>;

    // decrypt(key, ciphertext) → plaintext | error
    //   Decrypts a ciphertext and returns the plaintext.
    fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error>;

    // authenticate(key, message) → signature
    //   Computes a MAC of the given message.
    fn authenticate(&self, key: &[u8], message: &[u8]) -> Vec<u8>;
}

trait ECPrivateKeyPinUvAuthProtocol {
    fn private_key(&self) -> &EphemeralSecret;
    fn public_key(&self) -> &P256PublicKey;
    fn kdf(&self, bytes: &[u8]) -> Vec<u8>;
}

/// Common functionality between ECDH-based PIN/UV auth protocols (1 & 2)
trait ECDHPinUvAuthProtocol {
    fn ecdh(&self, peer_public_key: &cose::PublicKey) -> Result<Vec<u8>, Error>;
    fn encapsulate(
        &self,
        peer_public_key: &cose::PublicKey,
    ) -> Result<(cose::PublicKey, Vec<u8>), Error>;
    fn get_public_key(&self) -> cose::PublicKey;
}

pub struct PinUvAuthProtocolOne {
    private_key: EphemeralSecret,
    public_key: P256PublicKey,
}

impl PinUvAuthProtocolOne {
    pub fn new() -> Self {
        let private_key = EphemeralSecret::random(&mut OsRng);
        let public_key = private_key.public_key();
        Self {
            private_key,
            public_key,
        }
    }
}

impl ECPrivateKeyPinUvAuthProtocol for PinUvAuthProtocolOne {
    fn private_key(&self) -> &EphemeralSecret {
        &self.private_key
    }

    fn public_key(&self) -> &P256PublicKey {
        &self.public_key
    }

    /// kdf(Z) → sharedSecret
    fn kdf(&self, bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::default();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}

impl<P> ECDHPinUvAuthProtocol for P
where
    P: ECPrivateKeyPinUvAuthProtocol,
{
    #[instrument(skip_all)]
    fn encapsulate(
        &self,
        peer_public_key: &cose::PublicKey,
    ) -> Result<(cose::PublicKey, Vec<u8>), Error> {
        // Let sharedSecret be the result of calling ecdh(peerCoseKey). Return any resulting error.
        let shared_secret = self.ecdh(peer_public_key)?;

        // Return(getPublicKey(), sharedSecret)
        Ok((self.get_public_key(), shared_secret))
    }

    /// ecdh(peerCoseKey) → sharedSecret | error
    fn ecdh(&self, peer_public_key: &cose::PublicKey) -> Result<Vec<u8>, Error> {
        // Parse peerCoseKey as specified for getPublicKey, below, and produce a P-256 point, Y.
        // If unsuccessful, or if the resulting point is not on the curve, return error.
        let cose::PublicKey::EcdhEsHkdf256Key(peer_public_key) = peer_public_key else {
            error!(
                ?peer_public_key,
                "Unsupported peerCoseKey format. Only EcdhEsHkdf256Key is supported."
            );
            return Err(Error::Ctap(CtapError::Other));
        };
        let encoded_point = EncodedPoint::from_affine_coordinates(
            peer_public_key.x.as_bytes().into(),
            peer_public_key.y.as_bytes().into(),
            false,
        );
        let Some(peer_public_key) = P256PublicKey::from_encoded_point(&encoded_point).into() else {
            error!("Failed to parse public key.");
            return Err(Error::Ctap(CtapError::Other));
        };

        // Calculate xY, the shared point. (I.e. the scalar-multiplication of the peer’s point, Y, with the
        // local private key agreement key.)
        let shared = self.private_key().diffie_hellman(&peer_public_key);

        // Return kdf(Z).
        Ok(self.kdf(shared.raw_secret_bytes().as_bytes()))
    }

    /// getPublicKey()
    fn get_public_key(&self) -> cose::PublicKey {
        let point = EncodedPoint::from(self.public_key());
        let x: heapless::Vec<u8, 32> =
            heapless::Vec::from_slice(point.x().expect("Not the identity point").as_bytes())
                .unwrap();
        let y: heapless::Vec<u8, 32> =
            heapless::Vec::from_slice(point.y().expect("Not identity nor compressed").as_bytes())
                .unwrap();
        cose::PublicKey::EcdhEsHkdf256Key(cose::EcdhEsHkdf256PublicKey {
            x: x.into(),
            y: y.into(),
        })
    }
}

impl PinUvAuthProtocol for PinUvAuthProtocolOne {
    fn version(&self) -> Ctap2PinUvAuthProtocol {
        Ctap2PinUvAuthProtocol::One
    }

    #[instrument(skip_all)]
    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        // Return the AES-256-CBC encryption of demPlaintext using an all-zero IV.
        // (No padding is performed as the size of demPlaintext is required to be a multiple of the AES block length.)
        let iv: &[u8] = &[0; 16];
        let Ok(enc) = Aes256CbcEncryptor::new_from_slices(key, iv) else {
            error!(?key, "Invalid key for AES-256 encryption");
            return Err(Error::Ctap(CtapError::Other));
        };
        Ok(enc.encrypt_padded_vec_mut::<NoPadding>(plaintext))
    }

    #[instrument(skip_all)]
    fn authenticate(&self, key: &[u8], message: &[u8]) -> Vec<u8> {
        // Return the first 16 bytes of the result of computing HMAC-SHA-256 with the given key and message.
        let hmac = hmac_sha256(key, message);
        Vec::from(&hmac[..16])
    }

    #[instrument(skip_all)]
    fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        // If the size of demCiphertext is not a multiple of the AES block length, return error.
        // Otherwise return the AES-256-CBC decryption of demCiphertext using an all-zero IV.
        if ciphertext.len() % 16 != 0 {
            error!(
                ?ciphertext,
                "Ciphertext length is not a multiple of AES block length"
            );
            return Err(Error::Ctap(CtapError::Other));
        }

        let iv: &[u8] = &[0; 16];
        let Ok(dec) = Aes256CbcDecryptor::new_from_slices(key, iv) else {
            error!(?key, "Invalid key for AES-256 decryption");
            return Err(Error::Ctap(CtapError::Other));
        };
        let Ok(plaintext) = dec.decrypt_padded_vec_mut::<NoPadding>(ciphertext) else {
            error!("Unpad error while decrypting");
            return Err(Error::Ctap(CtapError::Other));
        };
        Ok(plaintext)
    }

    fn encapsulate(
        &self,
        peer_public_key: &cose::PublicKey,
    ) -> Result<(cose::PublicKey, Vec<u8>), Error> {
        <Self as ECDHPinUvAuthProtocol>::encapsulate(self, peer_public_key)
    }
}

pub struct PinUvAuthProtocolTwo {
    private_key: EphemeralSecret,
    public_key: P256PublicKey,
}

impl PinUvAuthProtocolTwo {
    pub fn new() -> Self {
        let private_key = EphemeralSecret::random(&mut OsRng);
        let public_key = private_key.public_key();
        Self {
            private_key,
            public_key,
        }
    }
}

impl ECPrivateKeyPinUvAuthProtocol for PinUvAuthProtocolTwo {
    fn private_key(&self) -> &EphemeralSecret {
        &self.private_key
    }

    fn public_key(&self) -> &P256PublicKey {
        &self.public_key
    }

    /// kdf(Z) → sharedSecret
    fn kdf(&self, ikm: &[u8]) -> Vec<u8> {
        // Returns:
        //   HKDF-SHA-256(salt = 32 zero bytes, IKM = Z, L = 32, info = "CTAP2 HMAC key") ||
        //   HKDF-SHA-256(salt = 32 zero bytes, IKM = Z, L = 32, info = "CTAP2 AES key")
        let salt: &[u8] = &[0u8; 32];
        let mut output = hkdf_sha256(Some(salt), ikm, "CTAP2 HMAC key".as_bytes());
        output.extend(hkdf_sha256(Some(salt), ikm, "CTAP2 AES key".as_bytes()));
        output
    }
}

impl PinUvAuthProtocol for PinUvAuthProtocolTwo {
    fn version(&self) -> Ctap2PinUvAuthProtocol {
        Ctap2PinUvAuthProtocol::Two
    }

    #[instrument(skip_all)]
    fn encapsulate(
        &self,
        peer_public_key: &cose::PublicKey,
    ) -> Result<(cose::PublicKey, Vec<u8>), Error> {
        <Self as ECDHPinUvAuthProtocol>::encapsulate(self, peer_public_key)
    }

    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        // Discard the first 32 bytes of key. (This selects the AES-key portion of the shared secret.)
        let key = &key[32..];

        // Let iv be a 16-byte, random bytestring.
        let iv: [u8; 16] = thread_rng().gen();

        // Let ct be the AES-256-CBC encryption of demPlaintext using key and iv.
        // (No padding is performed as the size of demPlaintext is required to be a multiple of the AES block length.)
        let Ok(enc) = Aes256CbcEncryptor::new_from_slices(key, &iv) else {
            error!(?key, "Invalid key for AES-256 encryption");
            return Err(Error::Ctap(CtapError::Other));
        };
        let ct = enc.encrypt_padded_vec_mut::<NoPadding>(plaintext);

        // Return iv || ct.
        let mut out = Vec::from(iv);
        out.extend(ct);
        Ok(out)
    }

    fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        // Discard the first 32 bytes of key. (This selects the AES-key portion of the shared secret.)
        let key = &key[32..];

        // If demPlaintext is less than 16 bytes in length, return an error
        if ciphertext.len() < 16 {
            error!({ len = ciphertext.len() }, "Invalid length for ciphertext");
            return Err(Error::Ctap(CtapError::Other));
        };

        // Split demPlaintext after the 16th byte to produce two subspans, iv and ct.
        let (iv, ciphertext) = ciphertext.split_at(16);

        // Return the AES-256-CBC decryption of ct using key and iv.
        let Ok(dec) = Aes256CbcDecryptor::new_from_slices(key, iv) else {
            error!(?key, "Invalid key for AES-256 decryption");
            return Err(Error::Ctap(CtapError::Other));
        };
        let Ok(plaintext) = dec.decrypt_padded_vec_mut::<NoPadding>(ciphertext) else {
            error!("Unpad error while decrypting");
            return Err(Error::Ctap(CtapError::Other));
        };
        Ok(plaintext)
    }

    fn authenticate(&self, key: &[u8], message: &[u8]) -> Vec<u8> {
        // If key is longer than 32 bytes, discard the excess. (This selects the HMAC-key portion of the shared secret.
        // When key is the pinUvAuthToken, it is exactly 32 bytes long and thus this step has no effect.)
        let key = &key[..32];

        // Return the result of computing HMAC-SHA-256 on key and message.
        hmac_sha256(key, message)
    }
}

/// hash(pin) -> LEFT(SHA-256(pin), 16)
pub fn pin_hash(pin: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::default();
    hasher.update(pin);
    let hashed = hasher.finalize().to_vec();
    Vec::from(&hashed[..16])
}

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut hmac = HmacSha256::new_from_slice(key).expect("Any key size is valid");
    hmac.update(message);
    hmac.finalize().into_bytes().to_vec()
}

pub fn hkdf_sha256(salt: Option<&[u8]>, ikm: &[u8], info: &[u8]) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(salt, &ikm);
    let mut okm = [0u8; 32]; // fixed L = 32
    hk.expand(info, &mut okm)
        .expect("32 is a valid length for Sha256 to output");
    Vec::from(okm)
}

#[async_trait]
pub trait PinManagement {
    async fn change_pin(&mut self, new_pin: String, timeout: Duration) -> Result<(), Error>;
}

#[async_trait]
impl<C> PinManagement for C
where
    C: Channel,
{
    async fn change_pin(&mut self, new_pin: String, timeout: Duration) -> Result<(), Error> {
        let get_info_response = self.ctap2_get_info().await?;

        // If the minPINLength member of the authenticatorGetInfo response is absent, then let platformMinPINLengthInCodePoints be 4.
        if new_pin.as_bytes().len() < get_info_response.min_pin_length.unwrap_or(4) as usize {
            // If platformCollectedPinLengthInCodePoints is less than platformMinPINLengthInCodePoints then the platform SHOULD display a "PIN too short" error message to the user.
            return Err(Error::Platform(PlatformError::PinTooShort));
        }

        // If the byte length of "newPin" is greater than the max UTF-8 representation limit of 63 bytes, then the platform SHOULD display a "PIN too long" error message to the user.
        if new_pin.as_bytes().len() >= 64 {
            return Err(Error::Platform(PlatformError::PinTooLong));
        }

        let Some(uv_proto) = select_uv_proto(&get_info_response).await else {
            error!("No supported PIN/UV auth protocols found");
            return Err(Error::Ctap(CtapError::Other));
        };

        let current_pin = match get_info_response.options.as_ref().unwrap().get("clientPin") {
            // Obtaining the current PIN, if one is set
            Some(true) => Some(
                obtain_pin(
                    self,
                    &get_info_response,
                    uv_proto.version(),
                    PinRequestReason::AuthenticatorPolicy,
                    timeout,
                )
                .await?,
            ),

            // No PIN set yet
            Some(false) => None,

            // Device does not support PIN
            None => {
                return Err(Error::Platform(PlatformError::PinNotSupported));
            }
        };

        // In preparation for obtaining pinUvAuthToken, the platform:
        // * Obtains a shared secret.
        let (public_key, shared_secret) = obtain_shared_secret(self, &uv_proto, timeout).await?;

        // paddedPin is newPin padded on the right with 0x00 bytes to make it 64 bytes long. (Since the maximum length of newPin is 63 bytes, there is always at least one byte of padding.)
        let mut padded_new_pin = new_pin.as_bytes().to_vec();
        padded_new_pin.resize(64, 0x00);

        // newPinEnc: the result of calling encrypt(shared secret, paddedPin) where
        let new_pin_enc = uv_proto.encrypt(&shared_secret, &padded_new_pin)?;

        let req = match current_pin {
            Some(curr_pin) => {
                // pinHashEnc: The result of calling encrypt(shared secret, LEFT(SHA-256(curPin), 16)).
                let pin_hash = pin_hash(&curr_pin);
                let pin_hash_enc = uv_proto.encrypt(&shared_secret, &pin_hash)?;

                // pinUvAuthParam: the result of calling authenticate(shared secret, newPinEnc || pinHashEnc)
                let uv_auth_param = uv_proto.authenticate(
                    &shared_secret,
                    &[new_pin_enc.as_slice(), pin_hash_enc.as_slice()].concat(),
                );

                Ctap2ClientPinRequest::new_change_pin(
                    uv_proto.version(),
                    &new_pin_enc,
                    &pin_hash_enc,
                    public_key,
                    &uv_auth_param,
                )
            }
            None => {
                // pinUvAuthParam: the result of calling authenticate(shared secret, newPinEnc).
                let uv_auth_param = uv_proto.authenticate(&shared_secret, &new_pin_enc);

                Ctap2ClientPinRequest::new_set_pin(
                    uv_proto.version(),
                    &new_pin_enc,
                    public_key,
                    &uv_auth_param,
                )
            }
        };

        // On success, this is an all-empty Ctap2ClientPinResponse
        let _ = self.ctap2_client_pin(&req, timeout).await?;
        Ok(())
    }
}
