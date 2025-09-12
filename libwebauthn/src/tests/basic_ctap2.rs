use std::time::Duration;

use crate::ops::webauthn::GetAssertionRequest;
use crate::proto::ctap2::Ctap2PublicKeyCredentialDescriptor;
use crate::transport::hid::get_virtual_device;
use crate::transport::{Channel, Device};
use crate::webauthn::WebAuthn;
use crate::UvUpdate;
use crate::{
    ops::webauthn::{MakeCredentialRequest, ResidentKeyRequirement, UserVerificationRequirement},
    proto::ctap2::{
        Ctap2CredentialType, Ctap2PublicKeyCredentialRpEntity, Ctap2PublicKeyCredentialUserEntity,
    },
};
use rand::{thread_rng, Rng};
use test_log::test;
use tokio::sync::broadcast::Receiver;

const TIMEOUT: Duration = Duration::from_secs(10);

async fn handle_updates(mut state_recv: Receiver<UvUpdate>) {
    // MakeCredential update
    assert_eq!(state_recv.recv().await, Ok(UvUpdate::PresenceRequired));
    // GetAssertion update
    assert_eq!(state_recv.recv().await, Ok(UvUpdate::PresenceRequired));
}

#[test(tokio::test)]
async fn test_webauthn_basic_ctap2() {
    let mut device = get_virtual_device();

    let user_id: [u8; 32] = thread_rng().gen();
    let challenge: [u8; 32] = thread_rng().gen();

    println!("Selected HID authenticator: {}", &device);
    let mut channel = device.channel().await.unwrap();
    channel.wink(TIMEOUT).await.unwrap();

    // Make Credentials ceremony
    let make_credentials_request = MakeCredentialRequest {
        origin: "example.org".to_owned(),
        hash: Vec::from(challenge),
        relying_party: Ctap2PublicKeyCredentialRpEntity::new("example.org", "example.org"),
        user: Ctap2PublicKeyCredentialUserEntity::new(&user_id, "mario.rossi", "Mario Rossi"),
        resident_key: Some(ResidentKeyRequirement::Discouraged),
        user_verification: UserVerificationRequirement::Preferred,
        algorithms: vec![Ctap2CredentialType::default()],
        exclude: None,
        extensions: None,
        timeout: TIMEOUT,
    };

    let state_recv = channel.get_ux_update_receiver();
    let update_handle = tokio::spawn(handle_updates(state_recv));

    let response = channel
        .webauthn_make_credential(&make_credentials_request)
        .await
        .expect("Failed to register credential");
    println!("WebAuthn MakeCredential response: {:?}", response);

    let credential: Ctap2PublicKeyCredentialDescriptor =
        (&response.authenticator_data).try_into().unwrap();
    let get_assertion = GetAssertionRequest {
        relying_party_id: "example.org".to_owned(),
        hash: Vec::from(challenge),
        allow: vec![credential],
        user_verification: UserVerificationRequirement::Discouraged,
        extensions: None,
        timeout: TIMEOUT,
    };

    let response = channel
        .webauthn_get_assertion(&get_assertion)
        .await
        .expect("Failed to sign in");
    println!("WebAuthn GetAssertion response: {:?}", response);
    // Keeping the update-recv alive until the end to check all updates
    update_handle.await.unwrap();
}
