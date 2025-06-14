use std::time::Duration;

use cosey as cose;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use tracing::{error, trace};
use x509_parser::nom::AsBytes;

use super::webauthn::MakeCredentialRequest;
use crate::fido::{AttestedCredentialData, AuthenticatorData, AuthenticatorDataFlags};
use crate::ops::webauthn::{
    GetAssertionRequest, GetAssertionResponse, MakeCredentialResponse, UserVerificationRequirement,
};
use crate::proto::ctap1::{Ctap1RegisterRequest, Ctap1SignRequest};
use crate::proto::ctap1::{Ctap1RegisterResponse, Ctap1SignResponse};
use crate::proto::ctap2::cbor;
use crate::proto::ctap2::{
    Ctap2AttestationStatement, Ctap2COSEAlgorithmIdentifier, Ctap2GetAssertionResponse,
    Ctap2MakeCredentialResponse, Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialType,
    FidoU2fAttestationStmt,
};
use crate::webauthn::{CtapError, Error};

// FIDO U2F operations can be aliased to CTAP1 requests, as they have no other representation.
pub type RegisterRequest = Ctap1RegisterRequest;
pub type RegisterResponse = Ctap1RegisterResponse;
pub type SignRequest = Ctap1SignRequest;
pub type SignResponse = Ctap1SignResponse;

impl SignRequest {
    pub fn new_upgraded(
        rp_id_hash: &[u8],
        challenge: &[u8],
        key_handle: &[u8],
        timeout: Duration,
    ) -> Self {
        Self {
            app_id_hash: Vec::from(rp_id_hash),
            challenge: Vec::from(challenge),
            key_handle: Vec::from(key_handle),
            timeout,
            require_user_presence: true,
        }
    }
}

pub trait UpgradableResponse<T, R> {
    fn try_upgrade(&self, request: &R) -> Result<T, Error>;
}

impl UpgradableResponse<MakeCredentialResponse, MakeCredentialRequest> for RegisterResponse {
    fn try_upgrade(
        &self,
        request: &MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Error> {
        // Let x9encodedUserPublicKeybe the user public key returned in the U2F registration response message [U2FRawMsgs].
        // Let coseEncodedCredentialPublicKey be the result of converting x9encodedUserPublicKey’s value
        // from ANS X9.62 / Sec-1 v2 uncompressed curve point representation [SEC1V2]
        // to COSE_Key representation ([RFC8152] Section 7).
        let Ok(encoded_point) = p256::EncodedPoint::from_bytes(&self.public_key) else {
            error!(?self.public_key, "Failed to parse public key as SEC-1 v2 encoded point");
            return Err(Error::Ctap(CtapError::Other));
        };
        let x: heapless::Vec<u8, 32> = heapless::Vec::from_slice(
            encoded_point
                .x()
                .expect("Not the identity point")
                .as_bytes(),
        )
        .unwrap();
        let y: heapless::Vec<u8, 32> = heapless::Vec::from_slice(
            encoded_point
                .y()
                .expect("Not identity nor compressed")
                .as_bytes(),
        )
        .unwrap();
        let cose_public_key = cose::PublicKey::P256Key(cose::P256PublicKey {
            x: x.into(),
            y: y.into(),
        });
        let cose_encoded_public_key = cbor::to_vec(&cose_public_key)?;
        assert!(cose_encoded_public_key.len() == 77);

        // Let attestedCredData be a byte string with following structure:
        //
        // Length (in bytes)   Description                        Value
        // -------------------------------------------------------------------------------------------------------------
        // 16                  The AAGUID of the authenticator.   Initialized with all zeros.
        // 2                   Byte length L of Credential ID     Initialized with credentialIdLength bytes.
        // credentialIdLength  Credential ID.                     Initialized with credentialId bytes.
        // 77                  The credential public key.         Initialized with coseEncodedCredentialPublicKey bytes.

        let attested_cred_data = AttestedCredentialData {
            aaguid: [0u8; 16], // aaguid zeros
            credential_id: self.key_handle.clone(),
            credential_public_key: cose_public_key,
        };

        // Initialize authenticatorData:
        // Let flags be a byte whose zeroth bit (bit 0, UP) is set, and whose sixth bit (bit 6, AT) is set,
        // and all other bits are zero (bit zero is the least significant bit)
        let flags =
            AuthenticatorDataFlags::USER_PRESENT | AuthenticatorDataFlags::ATTESTED_CREDENTIALS;

        // Let signCount be a 4-byte unsigned integer initialized to zero.
        let signature_count: u32 = 0;

        // Let authenticatorData be a byte string with the following structure:
        //
        // Length (in bytes)   Description                              Value
        // -------------------------------------------------------------------------------------------------------------
        // 32                  SHA-256 hash of the rp.id.               Initialized with rpIdHash bytes.
        // 1                   Flags                                    Initialized with flags' value.
        // 4                   Signature counter (signCount).           Initialized with signCount bytes.
        // Variable Length     Attested credential data.                Initialized with attestedCredData’s value.
        let mut hasher = Sha256::default();
        hasher.update(request.relying_party.id.as_bytes());
        let rp_id_hash = hasher.finalize().into();
        let authenticator_data = AuthenticatorData {
            rp_id_hash,
            flags,
            signature_count,
            attested_credential: Some(attested_cred_data),
            extensions: None,
        };

        // Let attestationStatement be a CBOR map (see "attStmtTemplate" in Generating an Attestation Object [WebAuthn])
        // with the following keys, whose values are as follows:
        // * Set "x5c" as an array of the one attestation cert extracted from CTAP1/U2F response.
        // * Set "sig" to be the "signature" bytes from the U2F registration response message [U2FRawMsgs].
        //   Note: An ASN.1-encoded ECDSA signature value ranges over 8–72 bytes in length. [U2FRawMsgs] incorrectly
        //   states a different length range.
        let attestation_statement = Ctap2AttestationStatement::FidoU2F(FidoU2fAttestationStmt {
            algorithm: Ctap2COSEAlgorithmIdentifier::ES256,
            signature: ByteBuf::from(self.signature.clone()),
            certificates: vec![ByteBuf::from(self.attestation.clone())],
        });

        // Let attestationObject be a CBOR map (see "attObj" in Generating an Attestation Object [WebAuthn]) with the
        // following keys, whose values are as follows:
        // * Set "authData" to authenticatorData.
        // * Set "fmt" to "fido-u2f".
        // * Set "attStmt" to attestationStatement.
        let resp = Ctap2MakeCredentialResponse {
            format: String::from("fido-u2f"),
            authenticator_data,
            attestation_statement,
            enterprise_attestation: None,
            large_blob_key: None,
        };
        Ok(resp.into_make_credential_output(request, None))
    }
}

impl UpgradableResponse<GetAssertionResponse, SignRequest> for SignResponse {
    fn try_upgrade(&self, request: &SignRequest) -> Result<GetAssertionResponse, Error> {
        // Generate authenticatorData from the U2F authentication response message received from the authenticator:

        // Copy bits 0 (the UP bit) and bit 1 from the CTAP2/U2F response user presence byte to bits 0 and 1 of the
        // CTAP2 flags, respectively. Set all other bits of flags to zero. Note: bit zero is the least significant bit.
        // See also Authenticator Data section of [WebAuthn].
        // up always set
        // bit 1 is unused, ignoring
        let flags = AuthenticatorDataFlags::USER_PRESENT;

        // Let signCount be a 4-byte unsigned integer initialized with CTAP1/U2F response counter field.
        let signature_count = self.counter;

        // Let authenticatorData is a byte string of following structure:
        // Length (in bytes)        Description                     Value
        // -------------------------------------------------------------------------------------------------------------
        // 32                       SHA-256 hash of the rp.id.      Initialized with rpIdHash bytes.
        // 1                        Flags                           Initialized with flags' value.
        // 4                        Signature counter (signCount)   Initialized with signCount bytes.
        let authenticator_data = AuthenticatorData {
            rp_id_hash: request.app_id_hash.clone().try_into().unwrap(),
            flags,
            signature_count,
            attested_credential: None,
            extensions: None,
        };

        // Let authenticatorGetAssertionResponse be a CBOR map with the following keys whose values are as follows: [..]
        let response = Ctap2GetAssertionResponse {
            credential_id: Some(Ctap2PublicKeyCredentialDescriptor {
                r#type: Ctap2PublicKeyCredentialType::PublicKey,
                id: ByteBuf::from(request.key_handle.clone()),
                transports: None,
            }),
            authenticator_data,
            signature: ByteBuf::from(self.signature.clone()),
            user: None,
            credentials_count: None,
            user_selected: None,
            large_blob_key: None,
            enterprise_attestation: None,
            attestation_statement: None,
        };

        // This isn't great, but we have no access to the original request, and need to construct
        // something like that here. In reality, we only need `extensions: None` currently.
        let orig_request = GetAssertionRequest {
            relying_party_id: String::new(), // We don't have access to that info here, but we don't need it either
            hash: request.app_id_hash.clone(),
            allow: vec![Ctap2PublicKeyCredentialDescriptor {
                r#type: Ctap2PublicKeyCredentialType::PublicKey,
                id: request.key_handle.clone().into(),
                transports: None,
            }],
            extensions: None,
            user_verification: if request.require_user_presence {
                UserVerificationRequirement::Required
            } else {
                UserVerificationRequirement::Preferred
            },
            timeout: request.timeout.clone(),
        };
        let upgraded_response = [response.into_assertion_output(&orig_request, None)]
            .as_slice()
            .into();

        trace!(?upgraded_response);
        Ok(upgraded_response)
    }
}
