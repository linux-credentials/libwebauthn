use std::time::Duration;

use libwebauthn::ops::webauthn::{
    GetAssertionRequest, GetAssertionResponse, MakeCredentialRequest, ResidentKeyRequirement,
    UserVerificationRequirement,
};
use libwebauthn::proto::ctap2::preflight::ctap2_preflight;
use libwebauthn::proto::ctap2::{
    Ctap2CredentialType, Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialType, Ctap2PublicKeyCredentialUserEntity,
};
use libwebauthn::proto::CtapError;
use libwebauthn::transport::hid::channel::HidChannel;
use libwebauthn::transport::{Channel, Device};
use libwebauthn::webauthn::{Error, WebAuthn};
use libwebauthn::UvUpdate;
use libwebauthn_tests::virt::get_virtual_device;
use rand::{thread_rng, Rng};
use serde_bytes::ByteBuf;
use test_log::test;
use tokio::sync::broadcast::Receiver;

const TIMEOUT: Duration = Duration::from_secs(10);

async fn expected_uv_updates(mut state_recv: Receiver<UvUpdate>, expected_updates: &[UvUpdate]) {
    for expected_update in expected_updates {
        let update = state_recv
            .recv()
            .await
            .expect("Failed to receive UV update");
        assert_eq!(expected_update, &update);
    }
}

async fn make_credential_call(
    channel: &mut HidChannel<'_>,
    user_id: &[u8],
    exclude_list: Option<Vec<Ctap2PublicKeyCredentialDescriptor>>,
) -> Result<(Ctap2PublicKeyCredentialDescriptor, [u8; 32]), Error> {
    let challenge: [u8; 32] = thread_rng().gen();
    let make_credentials_request = MakeCredentialRequest {
        origin: "example.org".to_owned(),
        challenge: Vec::from(challenge),
        relying_party: Ctap2PublicKeyCredentialRpEntity::new("example.org", "example.org"),
        user: Ctap2PublicKeyCredentialUserEntity::new(user_id, "mario.rossi", "Mario Rossi"),
        resident_key: Some(ResidentKeyRequirement::Discouraged),
        user_verification: UserVerificationRequirement::Preferred,
        algorithms: vec![Ctap2CredentialType::default()],
        exclude: exclude_list,
        extensions: None,
        timeout: TIMEOUT,
        top_origin: None,
    };

    let response = channel
        .webauthn_make_credential(&make_credentials_request)
        .await;
    response.map(|x| ((&x.authenticator_data).try_into().unwrap(), challenge))
}

async fn get_assertion_call(
    channel: &mut HidChannel<'_>,
    allow_list: Vec<Ctap2PublicKeyCredentialDescriptor>,
) -> Result<GetAssertionResponse, Error> {
    let challenge: [u8; 32] = thread_rng().gen();
    let get_assertion = GetAssertionRequest {
        origin: "example.org".to_owned(),
        relying_party_id: "example.org".to_owned(),
        challenge: Vec::from(challenge),
        allow: allow_list,
        user_verification: UserVerificationRequirement::Discouraged,
        extensions: None,
        timeout: TIMEOUT,
        top_origin: None,
    };

    channel.webauthn_get_assertion(&get_assertion).await
}

fn create_credential(id: &[u8]) -> Ctap2PublicKeyCredentialDescriptor {
    Ctap2PublicKeyCredentialDescriptor {
        r#type: Ctap2PublicKeyCredentialType::PublicKey,
        id: ByteBuf::from(id),
        transports: None,
    }
}

#[test(tokio::test)]
async fn preflight_no_exclude_list() {
    // Make credential with exclude_list: None. Should do nothing in preflight and return a credential
    let mut device = get_virtual_device();
    let mut channel = device.channel().await.unwrap();

    let user_id: [u8; 32] = thread_rng().gen();

    let state_recv = channel.get_ux_update_receiver();
    let hash: [u8; 32] = thread_rng().gen();
    let filtered_list = ctap2_preflight(&mut channel, &[], &hash, "example.org").await;
    assert!(filtered_list.is_empty());

    let res = make_credential_call(&mut channel, &user_id, None).await;

    expected_uv_updates(state_recv, &[UvUpdate::PresenceRequired]).await;

    assert!(res.is_ok());
}

#[test(tokio::test)]
async fn preflight_nonsense_exclude_list() {
    // Make credential with nonsense exclude_list. Should remove everything in preflight and return a credential

    let mut device = get_virtual_device();
    let mut channel = device.channel().await.unwrap();

    let user_id: [u8; 32] = thread_rng().gen();

    let state_recv = channel.get_ux_update_receiver();

    let exclude_list = vec![
        create_credential(&[9, 8, 7, 6, 5, 4, 3, 2, 1]),
        create_credential(&[8, 7, 6, 5, 4, 3, 2, 1, 9]),
        create_credential(&[7, 6, 5, 4, 3, 2, 1, 9, 8]),
    ];

    let hash: [u8; 32] = thread_rng().gen();
    let filtered_list = ctap2_preflight(&mut channel, &exclude_list, &hash, "example.org").await;
    assert!(filtered_list.is_empty());

    let res = make_credential_call(&mut channel, &user_id, Some(exclude_list)).await;

    expected_uv_updates(state_recv, &[UvUpdate::PresenceRequired]).await;

    assert!(res.is_ok());
}

#[test(tokio::test)]
async fn preflight_mixed_exclude_list() {
    // Make credential with a mixed exclude_list that contains 2 real ones. Should remove the two fake ones in preflight and return an error

    let mut device = get_virtual_device();
    let mut channel = device.channel().await.unwrap();

    let user_id: [u8; 32] = thread_rng().gen();

    let state_recv = channel.get_ux_update_receiver();

    let res = make_credential_call(&mut channel, &user_id, None).await;
    let (first_credential, _) = res.expect("Failed to register first credential");

    let res = make_credential_call(&mut channel, &user_id, None).await;
    let (second_credential, hash) = res.expect("Failed to register second credential");

    let exclude_list = vec![
        create_credential(&[9, 8, 7, 6, 5, 4, 3, 2, 1]),
        first_credential.clone(),
        create_credential(&[8, 7, 6, 5, 4, 3, 2, 1, 9]),
        second_credential.clone(),
        create_credential(&[7, 6, 5, 4, 3, 2, 1, 9, 8]),
    ];

    let filtered_list = ctap2_preflight(&mut channel, &exclude_list, &hash, "example.org").await;
    assert_eq!(filtered_list.len(), 2);
    assert_eq!(filtered_list[0].id, first_credential.id);
    assert_eq!(filtered_list[1].id, second_credential.id);

    let res = make_credential_call(&mut channel, &user_id, Some(exclude_list)).await;
    assert!(matches!(
        res,
        Err(Error::Ctap(CtapError::CredentialExcluded))
    ));

    expected_uv_updates(
        state_recv,
        &[
            UvUpdate::PresenceRequired,
            UvUpdate::PresenceRequired,
            UvUpdate::PresenceRequired,
        ],
    )
    .await;
}

#[test(tokio::test)]
async fn preflight_no_allow_list() {
    // Get assertion with allow_list: None. Should do nothing in preflight and return an error OR credentials, if a discoverable credential for example.org is present on the device

    let mut device = get_virtual_device();
    let mut channel = device.channel().await.unwrap();

    let user_id: [u8; 32] = thread_rng().gen();

    let state_recv = channel.get_ux_update_receiver();
    let res = make_credential_call(&mut channel, &user_id, None).await;
    let (_credential, hash) = res.expect("Failed to register first credential");

    let filtered_list = ctap2_preflight(&mut channel, &[], &hash, "example.org").await;
    assert!(filtered_list.is_empty());

    let allow_list = Vec::new();
    let res = get_assertion_call(&mut channel, allow_list).await;
    assert!(matches!(res, Err(Error::Ctap(CtapError::NoCredentials))));

    expected_uv_updates(
        state_recv,
        &[UvUpdate::PresenceRequired, UvUpdate::PresenceRequired],
    )
    .await;
}

#[test(tokio::test)]
async fn preflight_nonsense_allow_list() {
    // Get assertion with nonsense allow_list. Should remove everything in preflight and return an error, AND run a dummy request to provoke a touch

    let mut device = get_virtual_device();
    let mut channel = device.channel().await.unwrap();

    let user_id: [u8; 32] = thread_rng().gen();

    let state_recv = channel.get_ux_update_receiver();
    let res = make_credential_call(&mut channel, &user_id, None).await;
    let (_credential, hash) = res.expect("Failed to register first credential");

    let allow_list = vec![
        create_credential(&[9, 8, 7, 6, 5, 4, 3, 2, 1]),
        create_credential(&[8, 7, 6, 5, 4, 3, 2, 1, 9]),
        create_credential(&[7, 6, 5, 4, 3, 2, 1, 9, 8]),
    ];

    let filtered_list = ctap2_preflight(&mut channel, &allow_list, &hash, "example.org").await;
    assert!(filtered_list.is_empty());

    let res = get_assertion_call(&mut channel, allow_list).await;
    assert!(matches!(res, Err(Error::Ctap(CtapError::NoCredentials))));

    expected_uv_updates(
        state_recv,
        &[UvUpdate::PresenceRequired, UvUpdate::PresenceRequired],
    )
    .await;
}

#[test(tokio::test)]
async fn preflight_mixed_allow_list() {
    // Get assertion with a mixed allow_list that contains 2 real ones. Should remove the two fake ones in preflight

    let mut device = get_virtual_device();
    let mut channel = device.channel().await.unwrap();

    let user_id: [u8; 32] = thread_rng().gen();

    let state_recv = channel.get_ux_update_receiver();
    let (first_credential, _) = make_credential_call(&mut channel, &user_id, None)
        .await
        .expect("Failed to register first credential");
    let (second_credential, hash) = make_credential_call(&mut channel, &user_id, None)
        .await
        .expect("Failed to register second credential");

    let allow_list = vec![
        create_credential(&[9, 8, 7, 6, 5, 4, 3, 2, 1]),
        first_credential.clone(),
        create_credential(&[8, 7, 6, 5, 4, 3, 2, 1, 9]),
        second_credential.clone(),
    ];

    let filtered_list = ctap2_preflight(&mut channel, &allow_list, &hash, "example.org").await;
    assert_eq!(filtered_list.len(), 2);
    assert_eq!(filtered_list[0].id, first_credential.id);
    assert_eq!(filtered_list[1].id, second_credential.id);

    let res = get_assertion_call(&mut channel, allow_list)
        .await
        .expect("getAssertion call failed");
    // We have non-discoverable credentials here, so the authenticator
    // will return on the first one in the allow_list it finds
    assert_eq!(res.assertions.len(), 1);
    assert_eq!(
        res.assertions[0]
            .credential_id
            .as_ref()
            .expect("Assertion 0 has no credential ID")
            .id,
        filtered_list[0].id
    );

    expected_uv_updates(
        state_recv,
        &[UvUpdate::PresenceRequired, UvUpdate::PresenceRequired],
    )
    .await;
}
