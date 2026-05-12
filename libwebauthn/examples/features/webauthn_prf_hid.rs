use std::collections::HashMap;
use std::convert::TryInto;
use std::error::Error;
use std::time::Duration;

use libwebauthn::transport::hid::channel::HidChannel;
use rand::{thread_rng, Rng};

use libwebauthn::ops::webauthn::{
    GetAssertionRequest, GetAssertionRequestExtensions, MakeCredentialPrfInput,
    MakeCredentialRequest, MakeCredentialsRequestExtensions, PrfInput, PrfInputValue,
    ResidentKeyRequirement, UserVerificationRequirement,
};
use libwebauthn::proto::ctap2::{
    Ctap2CredentialType, Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialUserEntity,
};
use libwebauthn::transport::hid::list_devices;
use libwebauthn::transport::{Channel as _, Device};
use libwebauthn::webauthn::{Error as WebAuthnError, PlatformError, WebAuthn};

#[path = "../common/mod.rs"]
mod common;

const TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    common::setup_logging();

    let devices = list_devices().await.unwrap();
    println!("Devices found: {:?}", devices);

    let user_id: [u8; 32] = thread_rng().gen();
    let challenge: [u8; 32] = thread_rng().gen();

    let extensions = MakeCredentialsRequestExtensions {
        prf: Some(MakeCredentialPrfInput { eval: None }),
        ..Default::default()
    };

    for mut device in devices {
        println!("Selected HID authenticator: {}", &device);
        let mut channel = device.channel().await?;
        channel.wink(TIMEOUT).await?;

        let state_recv = channel.get_ux_update_receiver();
        tokio::spawn(common::handle_uv_updates(state_recv));

        let make_credentials_request = MakeCredentialRequest {
            challenge: Vec::from(challenge),
            origin: "example.org".to_owned(),
            top_origin: None,
            relying_party: Ctap2PublicKeyCredentialRpEntity::new("example.org", "example.org"),
            user: Ctap2PublicKeyCredentialUserEntity::new(&user_id, "mario.rossi", "Mario Rossi"),
            resident_key: Some(ResidentKeyRequirement::Required),
            user_verification: UserVerificationRequirement::Preferred,
            algorithms: vec![Ctap2CredentialType::default()],
            exclude: None,
            extensions: Some(extensions.clone()),
            timeout: TIMEOUT,
        };

        let response =
            retry_user_errors!(channel.webauthn_make_credential(&make_credentials_request))
                .unwrap();

        println!(
            "WebAuthn MakeCredential extensions: {:?}",
            response.authenticator_data.extensions
        );

        let credential: Ctap2PublicKeyCredentialDescriptor =
            (&response.authenticator_data).try_into().unwrap();

        // Test 1: eval_by_credential with the cred_id we got
        let mut eval_by_credential = HashMap::new();
        eval_by_credential.insert(
            base64_url::encode(&credential.id),
            PrfInputValue {
                first: vec![1; 32],
                second: None,
            },
        );
        run_success_test(
            &mut channel,
            &credential,
            &challenge,
            PrfInput {
                eval: None,
                eval_by_credential,
            },
            "eval_by_credential only",
        )
        .await;

        // Test 2: eval and eval_with_credential with cred_id we got
        let mut eval_by_credential = HashMap::new();
        eval_by_credential.insert(
            base64_url::encode(&credential.id),
            PrfInputValue {
                first: vec![1; 32],
                second: None,
            },
        );
        run_success_test(
            &mut channel,
            &credential,
            &challenge,
            PrfInput {
                eval: Some(PrfInputValue {
                    first: vec![2; 32],
                    second: None,
                }),
                eval_by_credential,
            },
            "eval and eval_by_credential",
        )
        .await;

        // Test 3: eval only
        run_success_test(
            &mut channel,
            &credential,
            &challenge,
            PrfInput {
                eval: Some(PrfInputValue {
                    first: vec![1; 32],
                    second: None,
                }),
                eval_by_credential: HashMap::new(),
            },
            "eval only",
        )
        .await;

        // Test 4: eval and a full list of eval_by_credential
        let mut eval_by_credential = HashMap::new();
        eval_by_credential.insert(
            base64_url::encode(&[5; 54]),
            PrfInputValue {
                first: vec![5; 32],
                second: None,
            },
        );
        eval_by_credential.insert(
            base64_url::encode(&[7; 54]),
            PrfInputValue {
                first: vec![7; 32],
                second: Some(vec![7; 32]),
            },
        );
        eval_by_credential.insert(
            base64_url::encode(&[8; 54]),
            PrfInputValue {
                first: vec![8; 32],
                second: Some(vec![8; 32]),
            },
        );
        eval_by_credential.insert(
            base64_url::encode(&credential.id),
            PrfInputValue {
                first: vec![1; 32],
                second: None,
            },
        );
        run_success_test(
            &mut channel,
            &credential,
            &challenge,
            PrfInput {
                eval: Some(PrfInputValue {
                    first: vec![2; 32],
                    second: None,
                }),
                eval_by_credential,
            },
            "eval and full list of eval_by_credential",
        )
        .await;

        // Test 5: eval and non-fitting list of eval_by_credential
        let mut eval_by_credential = HashMap::new();
        eval_by_credential.insert(
            base64_url::encode(&[5; 54]),
            PrfInputValue {
                first: vec![5; 32],
                second: None,
            },
        );
        eval_by_credential.insert(
            base64_url::encode(&[7; 54]),
            PrfInputValue {
                first: vec![7; 32],
                second: Some(vec![7; 32]),
            },
        );
        eval_by_credential.insert(
            base64_url::encode(&[8; 54]),
            PrfInputValue {
                first: vec![8; 32],
                second: Some(vec![8; 32]),
            },
        );
        run_success_test(
            &mut channel,
            &credential,
            &challenge,
            PrfInput {
                eval: Some(PrfInputValue {
                    first: vec![1; 32],
                    second: None,
                }),
                eval_by_credential,
            },
            "eval and non-fitting list of eval_by_credential",
        )
        .await;

        // Test 6: no eval and non-fitting list of eval_by_credential
        let mut eval_by_credential = HashMap::new();
        eval_by_credential.insert(
            base64_url::encode(&[5; 54]),
            PrfInputValue {
                first: vec![5; 32],
                second: None,
            },
        );
        eval_by_credential.insert(
            base64_url::encode(&[7; 54]),
            PrfInputValue {
                first: vec![7; 32],
                second: Some(vec![7; 32]),
            },
        );
        eval_by_credential.insert(
            base64_url::encode(&[8; 54]),
            PrfInputValue {
                first: vec![8; 32],
                second: Some(vec![8; 32]),
            },
        );
        run_success_test(
            &mut channel,
            &credential,
            &challenge,
            PrfInput {
                eval: None,
                eval_by_credential,
            },
            "No eval and non-fitting list of eval_by_credential (should have no extension output)",
        )
        .await;

        // Test 7: Wrongly encoded credential_id
        let mut eval_by_credential = HashMap::new();
        eval_by_credential.insert(
            String::from("ÄöoLfwekldß^"),
            PrfInputValue {
                first: vec![1; 32],
                second: None,
            },
        );
        run_failed_test(
            &mut channel,
            Some(&credential),
            &challenge,
            PrfInput {
                eval: Some(PrfInputValue {
                    first: vec![2; 32],
                    second: None,
                }),
                eval_by_credential,
            },
            "Wrongly encoded credential_id",
            WebAuthnError::Platform(PlatformError::SyntaxError),
        )
        .await;

        // Test 8: Empty credential_id
        let mut eval_by_credential = HashMap::new();
        eval_by_credential.insert(
            String::new(),
            PrfInputValue {
                first: vec![1; 32],
                second: None,
            },
        );
        run_failed_test(
            &mut channel,
            Some(&credential),
            &challenge,
            PrfInput {
                eval: None,
                eval_by_credential,
            },
            "Empty credential_id",
            WebAuthnError::Platform(PlatformError::SyntaxError),
        )
        .await;

        // Test 9: Empty allow_list, set eval_by_credential
        let mut eval_by_credential = HashMap::new();
        eval_by_credential.insert(
            String::new(),
            PrfInputValue {
                first: vec![1; 32],
                second: None,
            },
        );
        run_failed_test(
            &mut channel,
            None,
            &challenge,
            PrfInput {
                eval: None,
                eval_by_credential,
            },
            "Empty allow_list, set eval_by_credential",
            WebAuthnError::Platform(PlatformError::NotSupported),
        )
        .await;
    }
    Ok(())
}

async fn run_success_test(
    channel: &mut HidChannel<'_>,
    credential: &Ctap2PublicKeyCredentialDescriptor,
    challenge: &[u8; 32],
    prf: PrfInput,
    printoutput: &str,
) {
    let get_assertion = GetAssertionRequest {
        relying_party_id: "example.org".to_owned(),
        challenge: Vec::from(challenge),
        origin: "example.org".to_string(),
        top_origin: None,
        allow: vec![credential.clone()],
        user_verification: UserVerificationRequirement::Discouraged,
        extensions: Some(GetAssertionRequestExtensions {
            prf: Some(prf),
            ..Default::default()
        }),
        timeout: TIMEOUT,
    };

    let response = retry_user_errors!(channel.webauthn_get_assertion(&get_assertion)).unwrap();
    for (num, assertion) in response.assertions.iter().enumerate() {
        println!(
            "{num}. result of {printoutput}: {:?}",
            assertion.authenticator_data.extensions
        );
    }
}

async fn run_failed_test(
    channel: &mut HidChannel<'_>,
    credential: Option<&Ctap2PublicKeyCredentialDescriptor>,
    challenge: &[u8; 32],
    prf: PrfInput,
    printoutput: &str,
    expected_error: WebAuthnError,
) {
    let get_assertion = GetAssertionRequest {
        relying_party_id: "example.org".to_owned(),
        challenge: Vec::from(challenge),
        origin: "example.org".to_string(),
        top_origin: None,
        allow: credential.map(|x| vec![x.clone()]).unwrap_or_default(),
        user_verification: UserVerificationRequirement::Discouraged,
        extensions: Some(GetAssertionRequestExtensions {
            prf: Some(prf),
            ..Default::default()
        }),
        timeout: TIMEOUT,
    };

    let response = retry_user_errors!(channel.webauthn_get_assertion(&get_assertion))
        .map(|_| panic!("Success, even though it should have errored out!"));

    assert_eq!(response, Err(expected_error), "{printoutput}:");
    println!("Success for test: {printoutput}")
}
