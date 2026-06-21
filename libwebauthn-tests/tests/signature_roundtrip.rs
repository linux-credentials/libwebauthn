use std::time::Duration;

use libwebauthn::fido::AuthenticatorDataFlags;
use libwebauthn::ops::webauthn::{
    GetAssertionRequest, MakeCredentialRequest, MakeCredentialsRequestExtensions,
    ResidentKeyRequirement, UserVerificationRequirement, WebAuthnIDLResponse,
};
use libwebauthn::proto::ctap2::{
    cose, Ctap2, Ctap2AttestationStatement, Ctap2CredentialType,
    Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialUserEntity,
};
use libwebauthn::transport::{ChannelSettings, Device};
use libwebauthn::webauthn::WebAuthn;
use libwebauthn_tests::virt::get_virtual_device;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};
use test_log::test;
use x509_parser::prelude::{FromDer, SubjectPublicKeyInfo, X509Certificate};

const TIMEOUT: Duration = Duration::from_secs(10);

/// The attestation certificate the virtual authenticator is provisioned with.
const ATTESTATION_CERT: &[u8] = include_bytes!("../src/virt/data/fido-cert.der");

/// Reads the P-256 verifying key out of an `id-ecPublicKey` SPKI.
fn es256_key(spki: &SubjectPublicKeyInfo) -> VerifyingKey {
    VerifyingKey::from_sec1_bytes(spki.subject_public_key.data.as_ref())
        .expect("SPKI must carry a valid P-256 point")
}

/// `authenticatorData || SHA-256(clientDataJSON)`, the bytes a WebAuthn
/// signature is computed over (WebAuthn L3 6.3.3 and 8.2).
fn signed_bytes(authenticator_data: &[u8], client_data_json: &[u8]) -> Vec<u8> {
    let mut message = authenticator_data.to_vec();
    message.extend_from_slice(Sha256::digest(client_data_json).as_slice());
    message
}

fn verify_es256(key: &VerifyingKey, message: &[u8], der_signature: &[u8], label: &str) {
    let signature = Signature::from_der(der_signature)
        .unwrap_or_else(|e| panic!("{label}: signature is not DER ECDSA: {e}"));
    key.verify(message, &signature)
        .unwrap_or_else(|e| panic!("{label}: ES256 signature failed to verify: {e}"));
}

/// End-to-end signature verification against the in-process virtual
/// authenticator: the assertion signature over the credential key (WebAuthn L3
/// 6.3.3) and the packed attestation signature over the embedded certificate
/// (WebAuthn L3 8.2). The credential is registered with hmac-secret so the
/// signed authenticatorData carries an extensions block, exercising the
/// verbatim raw-bytes path from #249.
#[test(tokio::test)]
async fn test_ctap2_signature_roundtrip() {
    let mut device = get_virtual_device();
    let mut channel = device.channel(ChannelSettings::default()).await.unwrap();

    let info = channel.ctap2_get_info().await.expect("GetInfo");
    assert!(
        info.extensions.iter().flatten().any(|e| e == "hmac-secret"),
        "virtual authenticator must advertise hmac-secret"
    );

    let user_id: [u8; 32] = thread_rng().gen();
    let challenge: [u8; 32] = thread_rng().gen();

    let make_request = MakeCredentialRequest {
        challenge: Vec::from(challenge),
        origin: "example.org".to_owned(),
        top_origin: None,
        relying_party: Ctap2PublicKeyCredentialRpEntity::new("example.org", "example.org"),
        user: Ctap2PublicKeyCredentialUserEntity::new(&user_id, "alice", "Alice"),
        resident_key: Some(ResidentKeyRequirement::Discouraged),
        user_verification: UserVerificationRequirement::Preferred,
        algorithms: vec![Ctap2CredentialType::default()],
        attestation: None,
        exclude: None,
        extensions: Some(MakeCredentialsRequestExtensions {
            hmac_create_secret: Some(true),
            ..Default::default()
        }),
        timeout: TIMEOUT,
    };

    let registration = channel
        .webauthn_make_credential(&make_request)
        .await
        .expect("Failed to register credential");

    // The signed authenticatorData must carry an extensions block (#249).
    assert!(
        registration
            .authenticator_data
            .flags
            .contains(AuthenticatorDataFlags::EXTENSION_DATA),
        "attested authenticatorData must set the extension-data flag"
    );
    assert_eq!(
        registration
            .authenticator_data
            .extensions
            .as_ref()
            .and_then(|e| e.hmac_secret),
        Some(true),
        "credential must be created with hmac-secret"
    );
    assert!(
        registration.authenticator_data.raw.is_some(),
        "device authenticatorData must be preserved verbatim"
    );

    // Attestation path (WebAuthn L3 8.2): the authData embedded in the
    // client-emitted attestationObject must be byte-identical to the
    // authenticatorData surfaced alongside it, and the packed attStmt
    // signature must verify against the embedded attestation certificate.
    let idl = registration
        .to_idl_model(&make_request)
        .expect("attestation IDL model");
    let attestation_object = idl.response.attestation_object.as_slice();
    let attested_authenticator_data = idl.response.authenticator_data.as_slice();
    let registration_client_data = idl.response.client_data_json.as_slice();

    assert!(
        attestation_object
            .windows(attested_authenticator_data.len())
            .any(|w| w == attested_authenticator_data),
        "attestationObject must embed authData verbatim"
    );

    let (attestation_signature, x5c) = match &registration.attestation_statement {
        Ctap2AttestationStatement::PackedOrAndroid(stmt) => (
            stmt.signature.as_ref(),
            stmt.certificates
                .first()
                .expect("packed attStmt must contain an x5c certificate")
                .as_ref(),
        ),
        other => panic!("expected a packed attestation statement, got {other:?}"),
    };
    assert_eq!(
        x5c, ATTESTATION_CERT,
        "x5c must be the embedded attestation certificate"
    );

    let (_, certificate) = X509Certificate::from_der(x5c).expect("attestation certificate");
    let attestation_key = es256_key(certificate.public_key());
    verify_es256(
        &attestation_key,
        &signed_bytes(attested_authenticator_data, registration_client_data),
        attestation_signature,
        "attestation",
    );

    // Assertion path (WebAuthn L3 6.3.3): the assertion signature must verify
    // against the credential public key taken from the registration authData.
    let credential_cose = &registration
        .authenticator_data
        .attested_credential
        .as_ref()
        .expect("attested credential")
        .credential_public_key;
    let credential_spki = cose::to_spki(credential_cose)
        .expect("COSE key to SPKI")
        .expect("ES256 credential yields an SPKI");
    let (_, credential_spki) =
        SubjectPublicKeyInfo::from_der(&credential_spki).expect("credential SPKI");
    let credential_key = es256_key(&credential_spki);

    let credential: Ctap2PublicKeyCredentialDescriptor =
        (&registration.authenticator_data).try_into().unwrap();
    let get_assertion = GetAssertionRequest {
        relying_party_id: "example.org".to_owned(),
        challenge: Vec::from(challenge),
        origin: "example.org".to_owned(),
        top_origin: None,
        allow: vec![credential],
        user_verification: UserVerificationRequirement::Discouraged,
        extensions: None,
        timeout: TIMEOUT,
    };

    let assertion_response = channel
        .webauthn_get_assertion(&get_assertion)
        .await
        .expect("Failed to get assertion");
    let assertion = assertion_response
        .assertions
        .first()
        .expect("at least one assertion");

    let assertion_authenticator_data = assertion
        .authenticator_data
        .to_response_bytes()
        .expect("assertion authenticatorData");
    verify_es256(
        &credential_key,
        &signed_bytes(
            &assertion_authenticator_data,
            get_assertion.client_data_json().as_bytes(),
        ),
        &assertion.signature,
        "assertion",
    );
}
