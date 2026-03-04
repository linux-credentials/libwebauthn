use crate::pin::PinManagement;
use crate::proto::CtapError;
use crate::transport::hid::get_virtual_device;
use crate::transport::{Channel, Device};
use crate::webauthn::Error;
use test_log::test;
use tokio::sync::broadcast::error::TryRecvError;

use super::helpers::*;

#[test(tokio::test)]
async fn test_resident_key_create_and_discover() {
    let mut device = get_virtual_device();
    let mut channel = device.channel().await.unwrap();
    channel.change_pin(PIN.to_owned(), TIMEOUT).await.unwrap();

    let user_id = b"discoverable-user-1";
    let state_recv = channel.get_ux_update_receiver();
    let uv_handle = tokio::spawn(handle_updates(
        state_recv,
        vec![
            ExpectedUpdate::PinRequired,      // MakeCredential PIN
            ExpectedUpdate::PresenceRequired, // MakeCredential touch
            ExpectedUpdate::PresenceRequired, // GetAssertion touch (token cached)
        ],
    ));

    make_credential(&mut channel, user_id, "required", "required", None)
        .await
        .expect("MakeCredential failed");

    // Discoverable assertion: empty allow list
    let ga_resp = get_assertion(&mut channel, vec![], "required", None)
        .await
        .expect("Discoverable GetAssertion failed");

    assert_eq!(ga_resp.assertions.len(), 1);
    let user = ga_resp.assertions[0]
        .user
        .as_ref()
        .expect("Discoverable assertion should include user entity");
    assert_eq!(user.id.as_ref(), user_id);

    let mut rx = uv_handle.await.unwrap();
    assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
}

#[test(tokio::test)]
async fn test_resident_key_multiple_credentials_same_rp() {
    let mut device = get_virtual_device();
    let mut channel = device.channel().await.unwrap();
    channel.change_pin(PIN.to_owned(), TIMEOUT).await.unwrap();

    let user_a = b"multi-rk-user-a";
    let user_b = b"multi-rk-user-b";

    let state_recv = channel.get_ux_update_receiver();
    let uv_handle = tokio::spawn(handle_updates(
        state_recv,
        vec![
            ExpectedUpdate::PinRequired,      // First MakeCredential PIN
            ExpectedUpdate::PresenceRequired, // First MakeCredential touch
            ExpectedUpdate::PresenceRequired, // Second MakeCredential touch (token cached)
            ExpectedUpdate::PresenceRequired, // GetAssertion touch (token cached)
        ],
    ));

    let mc_a = make_credential(&mut channel, user_a, "required", "required", None)
        .await
        .expect("MakeCredential A failed");

    let mc_b = make_credential(&mut channel, user_b, "required", "required", None)
        .await
        .expect("MakeCredential B failed");

    let cred_a = credential_from(&mc_a);
    let cred_b = credential_from(&mc_b);
    assert_ne!(cred_a.id, cred_b.id, "Credentials should have distinct IDs");

    // Discoverable assertion returns both via GetNextAssertion
    let ga_resp = get_assertion(&mut channel, vec![], "required", None)
        .await
        .expect("Discoverable GetAssertion failed");

    assert_eq!(ga_resp.assertions.len(), 2);

    let returned_user_ids: Vec<&[u8]> = ga_resp
        .assertions
        .iter()
        .map(|a| {
            a.user
                .as_ref()
                .expect("Discoverable assertion should include user entity")
                .id
                .as_ref()
        })
        .collect();
    assert!(returned_user_ids.contains(&user_a.as_slice()));
    assert!(returned_user_ids.contains(&user_b.as_slice()));

    let mut rx = uv_handle.await.unwrap();
    assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
}

#[test(tokio::test)]
async fn test_non_discoverable_not_found_without_allow_list() {
    let mut device = get_virtual_device();
    let mut channel = device.channel().await.unwrap();

    let user_id = b"non-discoverable-user";
    let state_recv = channel.get_ux_update_receiver();
    let uv_handle = tokio::spawn(handle_updates(
        state_recv,
        vec![
            ExpectedUpdate::PresenceRequired, // MakeCredential touch
            ExpectedUpdate::PresenceRequired, // Empty-allow GetAssertion (dummy touch)
            ExpectedUpdate::PresenceRequired, // Allow-list GetAssertion touch
        ],
    ));

    let mc_resp = make_credential(&mut channel, user_id, "discouraged", "discouraged", None)
        .await
        .expect("MakeCredential failed");

    // Without allow list: should fail
    let result = get_assertion(&mut channel, vec![], "discouraged", None).await;
    assert!(
        matches!(result, Err(Error::Ctap(CtapError::NoCredentials))),
        "Expected NoCredentials, got: {:?}",
        result
    );

    // With allow list: should succeed
    let credential = credential_from(&mc_resp);
    get_assertion(&mut channel, vec![credential], "discouraged", None)
        .await
        .expect("GetAssertion with allow list failed");

    let mut rx = uv_handle.await.unwrap();
    assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
}
