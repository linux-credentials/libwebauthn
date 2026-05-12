use std::error::Error;
use std::time::Duration;

use rand::{thread_rng, Rng};
use serde_bytes::ByteBuf;

use libwebauthn::ops::webauthn::{
    GetAssertionRequest, GetAssertionRequestExtensions, GetAssertionResponse,
    MakeCredentialRequest, ResidentKeyRequirement, UserVerificationRequirement,
};
use libwebauthn::proto::ctap2::{
    Ctap2CredentialType, Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialType, Ctap2PublicKeyCredentialUserEntity,
};
use libwebauthn::transport::hid::list_devices;
use libwebauthn::transport::{Channel, Device};
use libwebauthn::webauthn::{CtapError, Error as WebAuthnError, WebAuthn};

#[path = "../common/mod.rs"]
mod common;

const TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    common::setup_logging();

    println!("-------------------------------------------------------");
    println!("Run this test with RUST_LOG=libwebauthn::proto::ctap2::preflight=info to verify the outputs");
    println!("-------------------------------------------------------");
    let devices = list_devices().await.unwrap();
    println!("Devices found: {:?}", devices);

    let user_id: [u8; 32] = thread_rng().gen();

    for mut device in devices {
        println!("Selected HID authenticator: {}", device);
        let mut channel = device.channel().await?;
        channel.wink(TIMEOUT).await?;

        let state_recv = channel.get_ux_update_receiver();
        tokio::spawn(common::handle_uv_updates(state_recv));

        println!("Make credential with exclude_list: None. Should do nothing in preflight and return a credential:");
        let res = make_credential_call(&mut channel, &user_id, None).await;
        assert!(res.is_ok());
        println!("Result: {res:?}");
        let first_credential = res.unwrap();

        println!("Make credential with nonsense exclude_list. Should remove everything in preflight and return a credential:");
        let exclude_list = vec![
            create_credential(&[9, 8, 7, 6, 5, 4, 3, 2, 1]),
            create_credential(&[8, 7, 6, 5, 4, 3, 2, 1, 9]),
            create_credential(&[7, 6, 5, 4, 3, 2, 1, 9, 8]),
        ];
        let res = make_credential_call(&mut channel, &user_id, Some(exclude_list)).await;
        assert!(res.is_ok());
        println!("Result: {res:?}");
        let second_credential = res.unwrap();

        println!("Make credential with a mixed exclude_list that contains 2 real ones. Should remove the two fake ones in preflight and return an error:");
        let exclude_list = vec![
            create_credential(&[9, 8, 7, 6, 5, 4, 3, 2, 1]),
            first_credential.clone(),
            create_credential(&[8, 7, 6, 5, 4, 3, 2, 1, 9]),
            second_credential.clone(),
        ];
        let res = make_credential_call(&mut channel, &user_id, Some(exclude_list)).await;
        assert!(matches!(
            res,
            Err(WebAuthnError::Ctap(CtapError::CredentialExcluded))
        ));
        println!("Result: {res:?}");

        println!("Get assertion with allow_list: None. Should do nothing in preflight and return an error OR credentials, if a discoverable credential for example.org is present on the device:");
        let res = get_assertion_call(&mut channel, Vec::new()).await;
        println!("Result: {res:?}");

        println!("Get assertion with nonsense allow_list. Should remove everything in preflight and return an error, AND run a dummy request to provoke a touch:");
        let allow_list = vec![
            create_credential(&[9, 8, 7, 6, 5, 4, 3, 2, 1]),
            create_credential(&[8, 7, 6, 5, 4, 3, 2, 1, 9]),
            create_credential(&[7, 6, 5, 4, 3, 2, 1, 9, 8]),
        ];
        let res = get_assertion_call(&mut channel, allow_list).await;
        assert!(matches!(
            res,
            Err(WebAuthnError::Ctap(CtapError::NoCredentials))
        ));
        println!("Result: {res:?}");

        println!("Get assertion with a mixed allow_list that contains 2 real ones. Should remove the two fake ones in preflight:");
        let allow_list = vec![
            create_credential(&[9, 8, 7, 6, 5, 4, 3, 2, 1]),
            first_credential.clone(),
            create_credential(&[8, 7, 6, 5, 4, 3, 2, 1, 9]),
            second_credential.clone(),
        ];
        let res = get_assertion_call(&mut channel, allow_list).await;
        assert!(res.is_ok());
        println!("Result: {res:?}");
    }
    Ok(())
}

async fn make_credential_call(
    channel: &mut impl Channel,
    user_id: &[u8],
    exclude_list: Option<Vec<Ctap2PublicKeyCredentialDescriptor>>,
) -> Result<Ctap2PublicKeyCredentialDescriptor, WebAuthnError> {
    let challenge: [u8; 32] = thread_rng().gen();
    let make_credentials_request = MakeCredentialRequest {
        challenge: Vec::from(challenge),
        origin: "example.org".to_owned(),
        top_origin: None,
        relying_party: Ctap2PublicKeyCredentialRpEntity::new("example.org", "example.org"),
        user: Ctap2PublicKeyCredentialUserEntity::new(user_id, "mario.rossi", "Mario Rossi"),
        resident_key: Some(ResidentKeyRequirement::Discouraged),
        user_verification: UserVerificationRequirement::Preferred,
        algorithms: vec![Ctap2CredentialType::default()],
        exclude: exclude_list,
        extensions: None,
        timeout: TIMEOUT,
    };

    retry_user_errors!(channel.webauthn_make_credential(&make_credentials_request))
        .map(|x| (&x.authenticator_data).try_into().unwrap())
}

async fn get_assertion_call(
    channel: &mut impl Channel,
    allow_list: Vec<Ctap2PublicKeyCredentialDescriptor>,
) -> Result<GetAssertionResponse, WebAuthnError> {
    let challenge: [u8; 32] = thread_rng().gen();
    let get_assertion = GetAssertionRequest {
        relying_party_id: "example.org".to_owned(),
        challenge: Vec::from(challenge),
        origin: "example.org".to_string(),
        top_origin: None,
        allow: allow_list,
        user_verification: UserVerificationRequirement::Discouraged,
        extensions: Some(GetAssertionRequestExtensions::default()),
        timeout: TIMEOUT,
    };

    retry_user_errors!(channel.webauthn_get_assertion(&get_assertion))
}

fn create_credential(id: &[u8]) -> Ctap2PublicKeyCredentialDescriptor {
    Ctap2PublicKeyCredentialDescriptor {
        r#type: Ctap2PublicKeyCredentialType::PublicKey,
        id: ByteBuf::from(id),
        transports: None,
    }
}
