use crate::ops::webauthn::CredentialPropsExtension;
use crate::transport::hid::get_virtual_device;
use crate::transport::{Channel, Device};
use test_log::test;
use tokio::sync::broadcast::error::TryRecvError;

use super::helpers::*;

const CRED_PROPS_EXT: &str = r#"{ "credProps": true }"#;

#[test(tokio::test)]
async fn test_cred_props_rk_required() {
    let mut device = get_virtual_device();
    let mut channel = device.channel().await.unwrap();

    let state_recv = channel.get_ux_update_receiver();
    let uv_handle = tokio::spawn(handle_updates(
        state_recv,
        vec![ExpectedUpdate::PresenceRequired],
    ));

    let mc_resp = make_credential(
        &mut channel,
        b"cred-props-rk-required",
        "required",
        "discouraged",
        Some(CRED_PROPS_EXT),
    )
    .await
    .expect("MakeCredential failed");

    assert_eq!(
        mc_resp.unsigned_extensions_output.cred_props,
        Some(CredentialPropsExtension { rk: Some(true) })
    );

    let mut rx = uv_handle.await.unwrap();
    assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
}

#[test(tokio::test)]
async fn test_cred_props_rk_discouraged() {
    let mut device = get_virtual_device();
    let mut channel = device.channel().await.unwrap();

    let state_recv = channel.get_ux_update_receiver();
    let uv_handle = tokio::spawn(handle_updates(
        state_recv,
        vec![ExpectedUpdate::PresenceRequired],
    ));

    let mc_resp = make_credential(
        &mut channel,
        b"cred-props-rk-discouraged",
        "discouraged",
        "discouraged",
        Some(CRED_PROPS_EXT),
    )
    .await
    .expect("MakeCredential failed");

    // FIDO 2.1 authenticator: platform can definitively say rk=false
    assert_eq!(
        mc_resp.unsigned_extensions_output.cred_props,
        Some(CredentialPropsExtension { rk: Some(false) })
    );

    let mut rx = uv_handle.await.unwrap();
    assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
}

#[test(tokio::test)]
async fn test_cred_props_not_requested() {
    let mut device = get_virtual_device();
    let mut channel = device.channel().await.unwrap();

    let state_recv = channel.get_ux_update_receiver();
    let uv_handle = tokio::spawn(handle_updates(
        state_recv,
        vec![ExpectedUpdate::PresenceRequired],
    ));

    let mc_resp = make_credential(
        &mut channel,
        b"cred-props-not-requested",
        "discouraged",
        "discouraged",
        None,
    )
    .await
    .expect("MakeCredential failed");

    assert_eq!(mc_resp.unsigned_extensions_output.cred_props, None);

    let mut rx = uv_handle.await.unwrap();
    assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
}
