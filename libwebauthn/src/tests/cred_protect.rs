use ctap_types::ctap2::credential_management::CredentialProtectionPolicy as Ctap2CredentialProtectionPolicy;

use crate::pin::PinManagement;
use crate::proto::CtapError;
use crate::transport::hid::get_virtual_device;
use crate::transport::{Channel, Device};
use crate::webauthn::Error;
use test_log::test;
use tokio::sync::broadcast::error::TryRecvError;

use super::helpers::*;

fn cred_protect_json(policy: &str) -> &'static str {
    match policy {
        "userVerificationOptional" => {
            r#"{ "credProtect": { "policy": "userVerificationOptional", "enforcePolicy": true } }"#
        }
        "userVerificationOptionalWithCredentialIDList" => {
            r#"{ "credProtect": { "policy": "userVerificationOptionalWithCredentialIDList", "enforcePolicy": true } }"#
        }
        "userVerificationRequired" => {
            r#"{ "credProtect": { "policy": "userVerificationRequired", "enforcePolicy": true } }"#
        }
        _ => panic!("Unknown credProtect policy: {policy}"),
    }
}

/// Level 1: userVerificationOptional — discoverable assertion without UV succeeds.
#[test(tokio::test)]
async fn test_cred_protect_level1() {
    let mut device = get_virtual_device();
    let mut channel = device.channel().await.unwrap();
    channel.change_pin(PIN.to_owned(), TIMEOUT).await.unwrap();

    let user_id = b"cp-level1-user";
    let state_recv = channel.get_ux_update_receiver();
    let uv_handle = tokio::spawn(handle_updates(
        state_recv,
        vec![
            ExpectedUpdate::PinRequired,      // MakeCredential PIN
            ExpectedUpdate::PresenceRequired, // MakeCredential touch
            ExpectedUpdate::PresenceRequired, // GetAssertion touch
        ],
    ));

    let ext = cred_protect_json("userVerificationOptional");
    let mc_resp = make_credential(&mut channel, user_id, "required", "preferred", Some(ext))
        .await
        .expect("MakeCredential with credProtect level 1 failed");

    assert_eq!(
        mc_resp
            .authenticator_data
            .extensions
            .as_ref()
            .and_then(|e| e.cred_protect),
        Some(Ctap2CredentialProtectionPolicy::Optional)
    );

    // Discoverable assertion without UV should succeed at level 1
    get_assertion(&mut channel, vec![], "discouraged", None)
        .await
        .expect("Level 1: discoverable assertion without UV should succeed");

    let mut rx = uv_handle.await.unwrap();
    assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
}

/// Level 2: userVerificationOptionalWithCredentialIDList —
/// with UV provided (cached PIN token), discoverable assertion succeeds.
/// Without UV it would fail, but the platform caches the PIN token from MakeCredential.
#[test(tokio::test)]
async fn test_cred_protect_level2() {
    let mut device = get_virtual_device();
    let mut channel = device.channel().await.unwrap();
    channel.change_pin(PIN.to_owned(), TIMEOUT).await.unwrap();

    let user_id = b"cp-level2-user";
    let state_recv = channel.get_ux_update_receiver();
    let uv_handle = tokio::spawn(handle_updates(
        state_recv,
        vec![
            ExpectedUpdate::PinRequired,      // MakeCredential PIN
            ExpectedUpdate::PresenceRequired, // MakeCredential touch
            ExpectedUpdate::PresenceRequired, // GetAssertion touch (UV via cached token)
        ],
    ));

    let ext = cred_protect_json("userVerificationOptionalWithCredentialIDList");
    let mc_resp = make_credential(&mut channel, user_id, "required", "preferred", Some(ext))
        .await
        .expect("MakeCredential with credProtect level 2 failed");

    assert_eq!(
        mc_resp
            .authenticator_data
            .extensions
            .as_ref()
            .and_then(|e| e.cred_protect),
        Some(Ctap2CredentialProtectionPolicy::OptionalWithCredentialIdList)
    );

    // Discoverable assertion succeeds because cached PIN token provides UV
    let ga_resp = get_assertion(&mut channel, vec![], "discouraged", None)
        .await
        .expect("Level 2: discoverable with UV (cached token) should succeed");

    assert_eq!(ga_resp.assertions.len(), 1);
    let user = ga_resp.assertions[0]
        .user
        .as_ref()
        .expect("Discoverable assertion should include user entity");
    assert_eq!(user.id.as_ref(), user_id);

    let mut rx = uv_handle.await.unwrap();
    assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
}

/// Level 3: userVerificationRequired — assertion without UV fails
/// even with the credential ID in the allow list.
#[test(tokio::test)]
async fn test_cred_protect_level3() {
    let mut device = get_virtual_device();
    let mut channel = device.channel().await.unwrap();
    channel.change_pin(PIN.to_owned(), TIMEOUT).await.unwrap();

    let user_id = b"cp-level3-user";
    let state_recv = channel.get_ux_update_receiver();
    let uv_handle = tokio::spawn(handle_updates(
        state_recv,
        vec![
            ExpectedUpdate::PinRequired,      // MakeCredential PIN
            ExpectedUpdate::PresenceRequired, // MakeCredential touch
            ExpectedUpdate::PresenceRequired, // GetAssertion (preflight filters credential, dummy touch)
        ],
    ));

    let ext = cred_protect_json("userVerificationRequired");
    let mc_resp = make_credential(&mut channel, user_id, "required", "required", Some(ext))
        .await
        .expect("MakeCredential with credProtect level 3 failed");

    assert_eq!(
        mc_resp
            .authenticator_data
            .extensions
            .as_ref()
            .and_then(|e| e.cred_protect),
        Some(Ctap2CredentialProtectionPolicy::Required)
    );

    // Assertion without UV should fail at level 3
    // (preflight cannot discover this credential without UV)
    let credential = credential_from(&mc_resp);
    let result = get_assertion(&mut channel, vec![credential], "discouraged", None).await;
    assert!(
        matches!(result, Err(Error::Ctap(CtapError::NoCredentials))),
        "Level 3: assertion without UV should fail, got: {:?}",
        result
    );

    let mut rx = uv_handle.await.unwrap();
    assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
}
