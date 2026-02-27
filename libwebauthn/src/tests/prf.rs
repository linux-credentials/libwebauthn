use std::collections::HashMap;
use std::time::Duration;

use crate::ops::webauthn::{
    GetAssertionRequest, GetAssertionRequestExtensions, MakeCredentialPrfInput,
    MakeCredentialPrfOutput, MakeCredentialsRequestExtensions, PRFValue, PrfInput,
};
use crate::pin::PinManagement;
use crate::proto::ctap2::{Ctap2PinUvAuthProtocol, Ctap2PublicKeyCredentialDescriptor};
use crate::transport::hid::channel::HidChannel;
use crate::transport::hid::get_virtual_device;
use crate::transport::{Channel, Device};
use crate::webauthn::{Error as WebAuthnError, PlatformError, WebAuthn};
use crate::UvUpdate;
use crate::{
    ops::webauthn::{MakeCredentialRequest, ResidentKeyRequirement, UserVerificationRequirement},
    proto::ctap2::{
        Ctap2CredentialType, Ctap2PublicKeyCredentialRpEntity, Ctap2PublicKeyCredentialUserEntity,
    },
};
use rand::{thread_rng, Rng};
use test_log::test;
use tokio::sync::broadcast::error::TryRecvError;
use tokio::sync::broadcast::Receiver;

const TIMEOUT: Duration = Duration::from_secs(10);

#[test(tokio::test)]
async fn test_webauthn_prf_no_pin_set() {
    let mut device = get_virtual_device();
    let mut channel = device.channel().await.unwrap();
    run_test_battery(&mut channel, false).await;
}

#[test(tokio::test)]
async fn test_webauthn_prf_with_pin_set() {
    let mut device = get_virtual_device();
    let mut channel = device.channel().await.unwrap();
    channel
        .change_pin(String::from("1234"), TIMEOUT)
        .await
        .unwrap();
    run_test_battery(&mut channel, true).await;
}

#[test(tokio::test)]
async fn test_webauthn_prf_with_pin_set_forced_pin_protocol_one() {
    let mut device = get_virtual_device();
    let mut channel = device.channel().await.unwrap();
    channel.set_forced_pin_protocol(Ctap2PinUvAuthProtocol::One);
    channel
        .change_pin(String::from("1234"), TIMEOUT)
        .await
        .unwrap();
    run_test_battery(&mut channel, true).await;
}

#[test(tokio::test)]
async fn test_webauthn_prf_with_pin_set_forced_pin_protocol_two() {
    let mut device = get_virtual_device();
    let mut channel = device.channel().await.unwrap();
    channel.set_forced_pin_protocol(Ctap2PinUvAuthProtocol::Two);
    channel
        .change_pin(String::from("1234"), TIMEOUT)
        .await
        .unwrap();
    run_test_battery(&mut channel, true).await;
}

enum UvUpdateShim {
    PresenceRequired,
    PinRequired,
}

async fn handle_updates(
    mut state_recv: Receiver<UvUpdate>,
    expected_updates: Vec<UvUpdateShim>,
) -> Receiver<UvUpdate> {
    for expected_update in expected_updates {
        let update = state_recv
            .recv()
            .await
            .expect("Failed to receive UV update");
        match expected_update {
            UvUpdateShim::PresenceRequired => assert_eq!(update, UvUpdate::PresenceRequired),
            UvUpdateShim::PinRequired => {
                if let UvUpdate::PinRequired(update) = update {
                    let _ = update.send_pin("1234");
                } else {
                    panic!("Did not get PinRequired-update as expected!");
                }
            }
        }
    }
    state_recv
}

async fn run_test_battery(channel: &mut HidChannel<'_>, using_pin: bool) {
    let user_id: [u8; 32] = thread_rng().gen();
    let challenge: [u8; 32] = thread_rng().gen();

    let extensions = MakeCredentialsRequestExtensions {
        prf: Some(MakeCredentialPrfInput {
            eval: Some(PRFValue {
                first: [1; 32],
                second: None,
            }),
        }),
        ..Default::default()
    };

    // Make Credentials ceremony
    let make_credentials_request = MakeCredentialRequest {
        origin: "example.org".to_owned(),
        challenge: Vec::from(challenge),
        relying_party: Ctap2PublicKeyCredentialRpEntity::new("example.org", "example.org"),
        user: Ctap2PublicKeyCredentialUserEntity::new(&user_id, "mario.rossi", "Mario Rossi"),
        resident_key: Some(ResidentKeyRequirement::Discouraged),
        user_verification: UserVerificationRequirement::Preferred,
        algorithms: vec![Ctap2CredentialType::default()],
        exclude: None,
        extensions: Some(extensions),
        timeout: TIMEOUT,
        cross_origin: None,
    };

    let state_recv = channel.get_ux_update_receiver();

    let mut expected_updates = Vec::new();
    // First make cred
    if using_pin {
        expected_updates.push(UvUpdateShim::PinRequired);
    }
    expected_updates.push(UvUpdateShim::PresenceRequired); // First MakeCredential

    // After this point, pinUvAuthToken should be cached by the channel, so no more PIN
    // requirements. The initial MakeCredential-call has a pinUvAuthToken valid for both
    // MakeCredential and GetAssertion (due to doing preflight), so it can be reused
    // for all GetAssertion calls afterwards.
    expected_updates.push(UvUpdateShim::PresenceRequired); // First GetAssertion w/o extensions
    expected_updates.push(UvUpdateShim::PresenceRequired); // Test 1
    expected_updates.push(UvUpdateShim::PresenceRequired); // Test 2
    expected_updates.push(UvUpdateShim::PresenceRequired); // Test 3
    expected_updates.push(UvUpdateShim::PresenceRequired); // Test 4
    expected_updates.push(UvUpdateShim::PresenceRequired); // Test 5
    expected_updates.push(UvUpdateShim::PresenceRequired); // Test 6

    // Tests 7-9 should have no update, as it errors out inside the platform

    let uv_handle = tokio::spawn(handle_updates(state_recv, expected_updates));

    let response = channel
        .webauthn_make_credential(&make_credentials_request)
        .await
        .expect("Failed to register credential");

    // Creating a credential with HMAC should work even if no PIN is set
    assert_eq!(
        response
            .authenticator_data
            .extensions
            .as_ref()
            .and_then(|e| e.hmac_secret),
        Some(true)
    );
    assert_eq!(
        response.unsigned_extensions_output.prf,
        Some(MakeCredentialPrfOutput {
            enabled: Some(true),
            results: None,
        })
    );

    let credential: Ctap2PublicKeyCredentialDescriptor =
        (&response.authenticator_data).try_into().unwrap();
    let get_assertion = GetAssertionRequest {
        relying_party_id: "example.org".to_owned(),
        origin: "example.org".to_owned(),
        challenge: Vec::from(challenge),
        allow: vec![credential.clone()],
        user_verification: UserVerificationRequirement::Preferred,
        extensions: None,
        timeout: TIMEOUT,
        cross_origin: None,
    };

    let _response = channel
        .webauthn_get_assertion(&get_assertion)
        .await
        .expect("Failed to sign in");

    // Test 1: eval_by_credential with the cred_id we got
    let eval = None;

    let mut eval_by_credential = HashMap::new();
    eval_by_credential.insert(
        base64_url::encode(&credential.id),
        PRFValue {
            first: [1; 32],
            second: None,
        },
    );
    let prf = PrfInput {
        eval,
        eval_by_credential,
    };
    run_success_test(
        channel,
        &credential,
        &challenge,
        prf,
        true,
        false,
        "eval_by_credential only",
    )
    .await;

    // Test 2: eval and eval_with_credential with cred_id we got
    let eval = Some(PRFValue {
        first: [2; 32],
        second: None,
    });

    let mut eval_by_credential = HashMap::new();
    eval_by_credential.insert(
        base64_url::encode(&credential.id),
        PRFValue {
            first: [1; 32],
            second: None,
        },
    );
    let prf = PrfInput {
        eval,
        eval_by_credential,
    };
    run_success_test(
        channel,
        &credential,
        &challenge,
        prf,
        true,
        false,
        "eval and eval_by_credential",
    )
    .await;

    // Test 3: eval only
    let eval = Some(PRFValue {
        first: [1; 32],
        second: None,
    });

    let eval_by_credential = HashMap::new();
    let prf = PrfInput {
        eval,
        eval_by_credential,
    };
    run_success_test(
        channel,
        &credential,
        &challenge,
        prf,
        true,
        false,
        "eval only",
    )
    .await;

    // Test 4: eval and a full list of eval_by_credential
    let eval = Some(PRFValue {
        first: [2; 32],
        second: None,
    });

    let mut eval_by_credential = HashMap::new();
    eval_by_credential.insert(
        base64_url::encode(&[5; 54]),
        PRFValue {
            first: [5; 32],
            second: None,
        },
    );
    eval_by_credential.insert(
        base64_url::encode(&[7; 54]),
        PRFValue {
            first: [7; 32],
            second: Some([7; 32]),
        },
    );
    eval_by_credential.insert(
        base64_url::encode(&[8; 54]),
        PRFValue {
            first: [8; 32],
            second: Some([8; 32]),
        },
    );
    eval_by_credential.insert(
        base64_url::encode(&credential.id),
        PRFValue {
            first: [1; 32],
            second: Some([7; 32]),
        },
    );
    let prf = PrfInput {
        eval,
        eval_by_credential,
    };
    run_success_test(
        channel,
        &credential,
        &challenge,
        prf,
        true,
        true,
        "eval and full list of eval_by_credential",
    )
    .await;

    // Test 5: eval and non-fitting list of eval_by_credential
    let eval = Some(PRFValue {
        first: [1; 32],
        second: None,
    });

    let mut eval_by_credential = HashMap::new();
    eval_by_credential.insert(
        base64_url::encode(&[5; 54]),
        PRFValue {
            first: [5; 32],
            second: None,
        },
    );
    eval_by_credential.insert(
        base64_url::encode(&[7; 54]),
        PRFValue {
            first: [7; 32],
            second: Some([7; 32]),
        },
    );
    eval_by_credential.insert(
        base64_url::encode(&[8; 54]),
        PRFValue {
            first: [8; 32],
            second: Some([8; 32]),
        },
    );
    let prf = PrfInput {
        eval,
        eval_by_credential,
    };
    run_success_test(
        channel,
        &credential,
        &challenge,
        prf,
        true,
        false,
        "eval and non-fitting list of eval_by_credential",
    )
    .await;

    // Test 6: no eval and non-fitting list of eval_by_credential
    let eval = None;

    let mut eval_by_credential = HashMap::new();
    eval_by_credential.insert(
        base64_url::encode(&[5; 54]),
        PRFValue {
            first: [5; 32],
            second: None,
        },
    );
    eval_by_credential.insert(
        base64_url::encode(&[7; 54]),
        PRFValue {
            first: [7; 32],
            second: Some([7; 32]),
        },
    );
    eval_by_credential.insert(
        base64_url::encode(&[8; 54]),
        PRFValue {
            first: [8; 32],
            second: Some([8; 32]),
        },
    );
    let prf = PrfInput {
        eval,
        eval_by_credential,
    };
    run_success_test(
        channel,
        &credential,
        &challenge,
        prf,
        false,
        false,
        "No eval and non-fitting list of eval_by_credential (should have no extension output)",
    )
    .await;

    // Test 7: Wrongly encoded credential_id
    let eval = Some(PRFValue {
        first: [2; 32],
        second: None,
    });

    let mut eval_by_credential = HashMap::new();
    eval_by_credential.insert(
        String::from("ÄöoLfwekldß^"),
        PRFValue {
            first: [1; 32],
            second: None,
        },
    );
    let prf = PrfInput {
        eval,
        eval_by_credential,
    };
    run_failed_test(
        channel,
        Some(&credential),
        &challenge,
        prf,
        "Wrongly encoded credential_id",
        WebAuthnError::Platform(PlatformError::SyntaxError),
    )
    .await;

    // Test 8: Empty credential_id
    let eval = None;
    let mut eval_by_credential = HashMap::new();
    eval_by_credential.insert(
        String::new(),
        PRFValue {
            first: [1; 32],
            second: None,
        },
    );
    let prf = PrfInput {
        eval,
        eval_by_credential,
    };
    run_failed_test(
        channel,
        Some(&credential),
        &challenge,
        prf,
        "Empty credential_id",
        WebAuthnError::Platform(PlatformError::SyntaxError),
    )
    .await;

    // Test 9: Empty allow_list, set eval_by_credential
    let eval = None;
    let mut eval_by_credential = HashMap::new();
    eval_by_credential.insert(
        String::new(),
        PRFValue {
            first: [1; 32],
            second: None,
        },
    );
    let prf = PrfInput {
        eval,
        eval_by_credential,
    };
    run_failed_test(
        channel,
        None,
        &challenge,
        prf,
        "Empty allow_list, set eval_by_credential",
        WebAuthnError::Platform(PlatformError::NotSupported),
    )
    .await;

    let mut state_recv = uv_handle.await.unwrap();
    // Verify that there is no lingering UV update in the queue
    assert_eq!(state_recv.try_recv(), Err(TryRecvError::Empty))
}

async fn run_success_test(
    channel: &mut HidChannel<'_>,
    credential: &Ctap2PublicKeyCredentialDescriptor,
    challenge: &[u8; 32],
    prf: PrfInput,
    expect_extensions: bool,
    expect_prf_second: bool,
    printoutput: &str,
) {
    let get_assertion = GetAssertionRequest {
        relying_party_id: "example.org".to_owned(),
        origin: "example.org".to_owned(),
        challenge: Vec::from(challenge),
        allow: vec![credential.clone()],
        user_verification: UserVerificationRequirement::Preferred,
        extensions: Some(GetAssertionRequestExtensions {
            prf: Some(prf),
            ..Default::default()
        }),
        timeout: TIMEOUT,
        cross_origin: None,
    };

    let response = channel
        .webauthn_get_assertion(&get_assertion)
        .await
        .expect("Failed to run PRF-test GetAssertion");
    assert_eq!(response.assertions.len(), 1, "Testcase: {}", printoutput);
    if expect_extensions {
        assert!(
            response.assertions[0].unsigned_extensions_output.is_some(),
            "Testcase: {}",
            printoutput
        );
        assert!(
            response.assertions[0]
                .unsigned_extensions_output
                .as_ref()
                .unwrap()
                .prf
                .is_some(),
            "Testcase: {}",
            printoutput
        );
        let prf = response.assertions[0]
            .unsigned_extensions_output
            .as_ref()
            .expect("Did not get unsigned_extensions_output")
            .prf
            .as_ref()
            .expect("Did not get prf inside unsigned_extensions_output");
        assert!(prf.results.is_some(), "Testcase: {}", printoutput);
        let results = prf.results.as_ref().unwrap();
        assert_ne!(results.first, [0; 32], "Testcase: {}", printoutput);
        if expect_prf_second {
            assert!(results.second.is_some(), "Testcase: {}", printoutput);
        } else {
            assert!(results.second.is_none(), "Testcase: {}", printoutput);
        }
    } else {
        assert!(
            response.assertions[0].unsigned_extensions_output.is_none(),
            "Testcase: {}",
            printoutput
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
        origin: "example.org".to_owned(),
        challenge: Vec::from(challenge),
        allow: credential.map(|x| vec![x.clone()]).unwrap_or_default(),
        user_verification: UserVerificationRequirement::Discouraged,
        extensions: Some(GetAssertionRequestExtensions {
            prf: Some(prf),
            ..Default::default()
        }),
        timeout: TIMEOUT,
        cross_origin: None,
    };

    let response: Result<(), WebAuthnError> = loop {
        match channel.webauthn_get_assertion(&get_assertion).await {
            Ok(_) => panic!("Success, even though it should have errored out!"),
            Err(WebAuthnError::Ctap(ctap_error)) => {
                if ctap_error.is_retryable_user_error() {
                    println!("Oops, try again! Error: {}", ctap_error);
                    continue;
                }
                break Err(WebAuthnError::Ctap(ctap_error));
            }
            Err(err) => break Err(err),
        };
    };

    assert_eq!(response, Err(expected_error), "{printoutput}:");
    println!("Success for test: {printoutput}")
}
