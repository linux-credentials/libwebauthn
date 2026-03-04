use crate::fido::AuthenticatorDataFlags;
use crate::pin::PinManagement;
use crate::proto::CtapError;
use crate::transport::hid::get_virtual_device;
use crate::transport::{Channel, Device};
use crate::webauthn::Error;
use test_log::test;
use tokio::sync::broadcast::error::TryRecvError;

use super::helpers::*;

#[test(tokio::test)]
async fn test_uv_required_with_pin() {
    let mut device = get_virtual_device();
    let mut channel = device.channel().await.unwrap();
    channel.change_pin(PIN.to_owned(), TIMEOUT).await.unwrap();

    let user_id = b"uv-required-user";
    let state_recv = channel.get_ux_update_receiver();
    let uv_handle = tokio::spawn(handle_updates(
        state_recv,
        vec![
            ExpectedUpdate::PinRequired,      // MakeCredential PIN
            ExpectedUpdate::PresenceRequired, // MakeCredential touch
            ExpectedUpdate::PresenceRequired, // GetAssertion touch (token cached)
        ],
    ));

    let mc_resp = make_credential(&mut channel, user_id, "discouraged", "required", None)
        .await
        .expect("MakeCredential failed");

    let mc_flags = &mc_resp.authenticator_data.flags;
    assert!(mc_flags.contains(AuthenticatorDataFlags::USER_PRESENT));
    assert!(mc_flags.contains(AuthenticatorDataFlags::USER_VERIFIED));

    let credential = credential_from(&mc_resp);
    let ga_resp = get_assertion(&mut channel, vec![credential], "required", None)
        .await
        .expect("GetAssertion failed");

    let ga_flags = &ga_resp.assertions[0].authenticator_data.flags;
    assert!(ga_flags.contains(AuthenticatorDataFlags::USER_PRESENT));
    assert!(ga_flags.contains(AuthenticatorDataFlags::USER_VERIFIED));

    let mut rx = uv_handle.await.unwrap();
    assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
}

#[test(tokio::test)]
async fn test_uv_discouraged_no_pin() {
    let mut device = get_virtual_device();
    let mut channel = device.channel().await.unwrap();

    let user_id = b"uv-discouraged-user";
    let state_recv = channel.get_ux_update_receiver();
    let uv_handle = tokio::spawn(handle_updates(
        state_recv,
        vec![
            ExpectedUpdate::PresenceRequired, // MakeCredential
            ExpectedUpdate::PresenceRequired, // GetAssertion
        ],
    ));

    let mc_resp = make_credential(&mut channel, user_id, "discouraged", "discouraged", None)
        .await
        .expect("MakeCredential failed");

    let mc_flags = &mc_resp.authenticator_data.flags;
    assert!(mc_flags.contains(AuthenticatorDataFlags::USER_PRESENT));
    assert!(!mc_flags.contains(AuthenticatorDataFlags::USER_VERIFIED));

    let credential = credential_from(&mc_resp);
    let ga_resp = get_assertion(&mut channel, vec![credential], "discouraged", None)
        .await
        .expect("GetAssertion failed");

    let ga_flags = &ga_resp.assertions[0].authenticator_data.flags;
    assert!(ga_flags.contains(AuthenticatorDataFlags::USER_PRESENT));
    assert!(!ga_flags.contains(AuthenticatorDataFlags::USER_VERIFIED));

    let mut rx = uv_handle.await.unwrap();
    assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
}

#[test(tokio::test)]
async fn test_uv_required_without_pin_fails() {
    let mut device = get_virtual_device();
    let mut channel = device.channel().await.unwrap();

    let user_id = b"uv-nopin-user";
    let result = make_credential(&mut channel, user_id, "discouraged", "required", None).await;

    assert!(
        matches!(result, Err(Error::Ctap(CtapError::PINNotSet))),
        "Expected PINNotSet error, got: {:?}",
        result
    );
}
