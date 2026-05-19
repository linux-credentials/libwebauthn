//! End-to-end test of WebAuthn largeBlob.read against the virt authenticator.

use std::time::Duration;

use libwebauthn::ops::webauthn::{
    GetAssertionLargeBlobExtension, GetAssertionRequest, GetAssertionRequestExtensions,
    MakeCredentialLargeBlobExtension, MakeCredentialLargeBlobExtensionInput, MakeCredentialRequest,
    MakeCredentialsRequestExtensions, ResidentKeyRequirement, UserVerificationRequirement,
};
use libwebauthn::proto::ctap2::{
    Ctap2, Ctap2CredentialType, Ctap2GetAssertionRequest, Ctap2LargeBlobsRequest,
    Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialUserEntity,
};
use libwebauthn::transport::{Channel, Device};
use libwebauthn::webauthn::WebAuthn;
use libwebauthn::UvUpdate;
use libwebauthn_tests::virt::get_virtual_device;
use rand::{thread_rng, Rng};
use test_log::test;
use tokio::sync::broadcast::Receiver;

const TIMEOUT: Duration = Duration::from_secs(10);
const RP: &str = "example.org";

async fn handle_updates(mut state_recv: Receiver<UvUpdate>) {
    // MakeCredential update
    assert_eq!(state_recv.recv().await, Ok(UvUpdate::PresenceRequired));
    // GetAssertion update
    assert_eq!(state_recv.recv().await, Ok(UvUpdate::PresenceRequired));
}

#[test(tokio::test)]
async fn test_webauthn_large_blob_read_returns_planted_blob() {
    let mut device = get_virtual_device();
    let mut channel = device.channel().await.unwrap();

    let user_id: [u8; 32] = thread_rng().gen();
    let challenge: [u8; 32] = thread_rng().gen();

    let make = MakeCredentialRequest {
        origin: RP.into(),
        challenge: challenge.to_vec(),
        relying_party: Ctap2PublicKeyCredentialRpEntity::new(RP, RP),
        user: Ctap2PublicKeyCredentialUserEntity::new(&user_id, "alice", "Alice"),
        resident_key: Some(ResidentKeyRequirement::Required),
        user_verification: UserVerificationRequirement::Discouraged,
        algorithms: vec![Ctap2CredentialType::default()],
        exclude: None,
        extensions: Some(MakeCredentialsRequestExtensions {
            large_blob: Some(MakeCredentialLargeBlobExtensionInput {
                support: MakeCredentialLargeBlobExtension::Required,
            }),
            ..Default::default()
        }),
        timeout: TIMEOUT,
        top_origin: None,
    };

    let state_recv = channel.get_ux_update_receiver();
    let update_handle = tokio::spawn(handle_updates(state_recv));

    let response = channel
        .webauthn_make_credential(&make)
        .await
        .expect("MakeCredential should succeed");
    assert_eq!(
        response
            .unsigned_extensions_output
            .large_blob
            .as_ref()
            .and_then(|lb| lb.supported),
        Some(true),
        "device must report largeBlob.supported=true"
    );
    let credential: Ctap2PublicKeyCredentialDescriptor =
        (&response.authenticator_data).try_into().unwrap();

    let key = capture_large_blob_key(&mut channel, &credential, &challenge).await;
    let plaintext = b"hello, planted largeBlob".to_vec();
    let nonce: [u8; 12] = thread_rng().gen();
    let serialized = encode_serialized_array(&[encode_entry(&key, &nonce, &plaintext)]);
    plant_large_blob_array(&mut channel, serialized).await;

    let ga = GetAssertionRequest {
        relying_party_id: RP.into(),
        origin: RP.into(),
        challenge: challenge.to_vec(),
        allow: vec![credential],
        user_verification: UserVerificationRequirement::Discouraged,
        extensions: Some(GetAssertionRequestExtensions {
            appid: None,
            cred_blob: false,
            prf: None,
            large_blob: Some(GetAssertionLargeBlobExtension::Read),
        }),
        timeout: TIMEOUT,
        top_origin: None,
    };
    let ga_response = channel
        .webauthn_get_assertion(&ga)
        .await
        .expect("GetAssertion should succeed");
    let blob = ga_response.assertions[0]
        .unsigned_extensions_output
        .as_ref()
        .and_then(|u| u.large_blob.as_ref())
        .and_then(|lb| lb.blob.as_ref())
        .expect("largeBlob.blob populated");
    assert_eq!(blob.as_slice(), plaintext.as_slice());

    update_handle.await.unwrap();
}

/// Capture the per-credential AES key via a direct CTAP GetAssertion.
async fn capture_large_blob_key(
    channel: &mut libwebauthn::transport::hid::channel::HidChannel<'_>,
    credential: &Ctap2PublicKeyCredentialDescriptor,
    challenge: &[u8; 32],
) -> [u8; 32] {
    let ga_for_key = GetAssertionRequest {
        relying_party_id: RP.into(),
        origin: RP.into(),
        challenge: challenge.to_vec(),
        allow: vec![credential.clone()],
        user_verification: UserVerificationRequirement::Discouraged,
        extensions: Some(GetAssertionRequestExtensions {
            appid: None,
            cred_blob: false,
            prf: None,
            large_blob: Some(GetAssertionLargeBlobExtension::Read),
        }),
        timeout: TIMEOUT,
        top_origin: None,
    };
    let ctap_req: Ctap2GetAssertionRequest = ga_for_key.into();
    let ctap_resp = channel
        .ctap2_get_assertion(&ctap_req, TIMEOUT)
        .await
        .expect("CTAP get_assertion succeeds");
    let key_buf = ctap_resp
        .large_blob_key
        .expect("device returns largeBlobKey when extension requested");
    key_buf
        .as_slice()
        .try_into()
        .expect("largeBlobKey is 32 bytes")
}

/// Plant a serialized largeBlobArray via direct CTAP set (no-PIN path).
async fn plant_large_blob_array(
    channel: &mut libwebauthn::transport::hid::channel::HidChannel<'_>,
    serialized: Vec<u8>,
) {
    let length = serialized.len() as u32;
    let req = Ctap2LargeBlobsRequest {
        get: None,
        set: Some(serde_bytes::ByteBuf::from(serialized)),
        offset: 0,
        length: Some(length),
        pin_uv_auth_param: None,
        pin_uv_auth_protocol: None,
    };
    channel
        .ctap2_large_blobs(&req, TIMEOUT)
        .await
        .expect("authenticatorLargeBlobs(set) succeeds without PIN");
}

/// Encode one largeBlobMap entry per CTAP 2.1 §6.10.3.
fn encode_entry(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use serde_cbor_2::value::Value as CborVal;
    use std::collections::BTreeMap;
    use std::io::Write;

    let mut compressed = Vec::new();
    {
        let mut enc = DeflateEncoder::new(&mut compressed, Compression::default());
        enc.write_all(plaintext).unwrap();
        enc.finish().unwrap();
    }
    let mut ad = b"blob".to_vec();
    ad.extend_from_slice(&(plaintext.len() as u64).to_le_bytes());
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            aes_gcm::aead::Payload {
                msg: &compressed,
                aad: &ad,
            },
        )
        .unwrap();

    let mut map = BTreeMap::new();
    map.insert(CborVal::Integer(1), CborVal::Bytes(ciphertext));
    map.insert(CborVal::Integer(2), CborVal::Bytes(nonce.to_vec()));
    map.insert(
        CborVal::Integer(3),
        CborVal::Integer(plaintext.len() as i128),
    );
    let mut buf = Vec::new();
    serde_cbor_2::to_writer(&mut buf, &CborVal::Map(map)).unwrap();
    buf
}

/// Wrap entries in a CBOR array + 16-byte left-SHA-256 trailer (CTAP 2.1 §6.10.3).
fn encode_serialized_array(entries: &[Vec<u8>]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    assert!(
        entries.len() <= 23,
        "test fixture uses short-form CBOR array"
    );
    let mut out = vec![0x80 | entries.len() as u8];
    for e in entries {
        out.extend_from_slice(e);
    }
    let h = Sha256::digest(&out);
    out.extend_from_slice(&h[..16]);
    out
}
