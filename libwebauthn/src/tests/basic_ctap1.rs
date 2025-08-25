use std::time::Duration;

use crate::ops::u2f::{RegisterRequest, SignRequest};
use crate::transport::hid::get_virtual_device;
use crate::transport::{Channel, Device};
use crate::u2f::U2F;
use crate::UvUpdate;
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
    let mut channel = device.channel().await.unwrap();
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
