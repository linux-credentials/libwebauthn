use std::time::Duration;

use libwebauthn::ops::u2f::{RegisterRequest, SignRequest};
use libwebauthn::transport::{Channel, ChannelSettings, Device};
use libwebauthn::u2f::U2F;
use libwebauthn::webauthn::{CtapError, WebAuthnError};
use libwebauthn::UvUpdate;
use libwebauthn_tests::virt::get_virtual_device;
use tokio::sync::broadcast::Receiver;

const TIMEOUT: Duration = Duration::from_secs(10);

async fn handle_updates(mut state_recv: Receiver<UvUpdate>) {
    // MakeCredential update
    assert_eq!(state_recv.recv().await, Ok(UvUpdate::PresenceRequired));
    // GetAssertion update
    assert_eq!(state_recv.recv().await, Ok(UvUpdate::PresenceRequired));
}

#[tokio::test]
async fn test_webauthn_basic_ctap1() {
    let mut device = get_virtual_device();

    println!("Selected HID authenticator: {}", &device);
    let mut channel = device.channel(ChannelSettings::default()).await.unwrap();
    channel.wink(TIMEOUT).await.unwrap();

    const APP_ID: &str = "https://foo.example.org";
    let challenge: &[u8] =
        &base64_url::decode("1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70").unwrap();
    // Registration ceremony
    let register_request = RegisterRequest::new_u2f_v2(APP_ID, challenge, vec![], TIMEOUT, false);

    let state_recv = channel.get_ux_update_receiver();
    let update_handle = tokio::spawn(handle_updates(state_recv));

    let response = channel
        .u2f_register(&register_request)
        .await
        .expect("Failed to register credential");
    println!("WebAuthn U2F register response: {:?}", response);

    let new_key = response
        .as_registered_key()
        .expect("Failed to get credential ID from register response");
    let sign_request = SignRequest::new(APP_ID, challenge, &new_key.key_handle, TIMEOUT, true);
    let response = channel
        .u2f_sign(&sign_request)
        .await
        .expect("Failed to sign in");
    println!("WebAuthn U2F sign response: {:?}", response);
    // Keeping the update-recv alive until the end to check all updates
    update_handle.await.unwrap();
}

async fn drain_updates(mut state_recv: Receiver<UvUpdate>) {
    while state_recv.recv().await.is_ok() {}
}

#[tokio::test]
async fn test_webauthn_ctap1_exclude_list() {
    let mut device = get_virtual_device();
    let mut channel = device.channel(ChannelSettings::default()).await.unwrap();

    const APP_ID: &str = "https://foo.example.org";
    let challenge: &[u8] =
        &base64_url::decode("1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70").unwrap();

    let drain_handle = tokio::spawn(drain_updates(channel.get_ux_update_receiver()));

    let register_request = RegisterRequest::new_u2f_v2(APP_ID, challenge, vec![], TIMEOUT, false);
    let response = channel
        .u2f_register(&register_request)
        .await
        .expect("Failed to register credential");
    let registered_key = response
        .as_registered_key()
        .expect("Failed to get credential ID from register response");

    // Preflight must reject an excluded credential.
    let excluded_request =
        RegisterRequest::new_u2f_v2(APP_ID, challenge, vec![registered_key], TIMEOUT, false);
    let result = channel.u2f_register(&excluded_request).await;
    assert!(
        matches!(
            result,
            Err(WebAuthnError::Ctap(CtapError::CredentialExcluded))
        ),
        "expected CredentialExcluded, got {:?}",
        result
    );

    drain_handle.abort();
}
