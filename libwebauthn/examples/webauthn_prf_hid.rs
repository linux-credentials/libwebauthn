use std::collections::HashMap;
use std::convert::TryInto;
use std::error::Error;
use std::io::{self, Write};
use std::time::Duration;

use libwebauthn::transport::hid::channel::HidChannel;
use libwebauthn::UvUpdate;
use rand::{thread_rng, Rng};
use text_io::read;
use tokio::sync::broadcast::Receiver;
use tracing_subscriber::{self, EnvFilter};

use libwebauthn::ops::webauthn::{
    GetAssertionHmacOrPrfInput, GetAssertionRequest, GetAssertionRequestExtensions,
    MakeCredentialPrfInput, MakeCredentialRequest, MakeCredentialsRequestExtensions, PRFValue,
    PrfInput, ResidentKeyRequirement, UserVerificationRequirement,
};
use libwebauthn::pin::PinRequestReason;
use libwebauthn::proto::ctap2::{
    Ctap2CredentialType, Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialUserEntity,
};
use libwebauthn::transport::hid::list_devices;
use libwebauthn::transport::{Channel as _, Device};
use libwebauthn::webauthn::{Error as WebAuthnError, PlatformError, WebAuthn};

const TIMEOUT: Duration = Duration::from_secs(10);

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .without_time()
        .init();
}

async fn handle_updates(mut state_recv: Receiver<UvUpdate>) {
    while let Ok(update) = state_recv.recv().await {
        match update {
            UvUpdate::PresenceRequired => println!("Please touch your device!"),
            UvUpdate::UvRetry { attempts_left } => {
                print!("UV failed.");
                if let Some(attempts_left) = attempts_left {
                    print!(" You have {attempts_left} attempts left.");
                }
            }
            UvUpdate::PinRequired(update) => {
                let mut attempts_str = String::new();
                if let Some(attempts) = update.attempts_left {
                    attempts_str = format!(". You have {attempts} attempts left!");
                };

                match update.reason {
                    PinRequestReason::RelyingPartyRequest => println!("RP required a PIN."),
                    PinRequestReason::AuthenticatorPolicy => {
                        println!("Your device requires a PIN.")
                    }
                    PinRequestReason::FallbackFromUV => {
                        println!("UV failed too often and is blocked. Falling back to PIN.")
                    }
                }
                print!("PIN: Please enter the PIN for your authenticator{attempts_str}: ");
                io::stdout().flush().unwrap();
                let pin_raw: String = read!("{}\n");

                if pin_raw.is_empty() {
                    println!("PIN: No PIN provided, cancelling operation.");
                    update.cancel();
                } else {
                    let _ = update.send_pin(&pin_raw);
                }
            }
        }
    }
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    setup_logging();

    let devices = list_devices().await.unwrap();
    println!("Devices found: {:?}", devices);

    let user_id: [u8; 32] = thread_rng().gen();
    let challenge: [u8; 32] = thread_rng().gen();

    let extensions = MakeCredentialsRequestExtensions {
        prf: Some(MakeCredentialPrfInput { _eval: None }),
        ..Default::default()
    };

    for mut device in devices {
        println!("Selected HID authenticator: {}", &device);
        let mut channel = device.channel().await?;
        channel.wink(TIMEOUT).await?;

        let state_recv = channel.get_ux_update_receiver();
        tokio::spawn(handle_updates(state_recv));

        // Make Credentials ceremony
        let make_credentials_request = MakeCredentialRequest {
            origin: "example.org".to_owned(),
            hash: Vec::from(challenge),
            relying_party: Ctap2PublicKeyCredentialRpEntity::new("example.org", "example.org"),
            user: Ctap2PublicKeyCredentialUserEntity::new(&user_id, "mario.rossi", "Mario Rossi"),
            resident_key: Some(ResidentKeyRequirement::Required),
            user_verification: UserVerificationRequirement::Preferred,
            algorithms: vec![Ctap2CredentialType::default()],
            exclude: None,
            extensions: Some(extensions.clone()),
            timeout: TIMEOUT,
        };

        let response = loop {
            match channel
                .webauthn_make_credential(&make_credentials_request)
                .await
            {
                Ok(response) => break Ok(response),
                Err(WebAuthnError::Ctap(ctap_error)) => {
                    if ctap_error.is_retryable_user_error() {
                        println!("Oops, try again! Error: {}", ctap_error);
                        continue;
                    }
                    break Err(WebAuthnError::Ctap(ctap_error));
                }
                Err(err) => break Err(err),
            };
        }
        .unwrap();

        println!(
            "WebAuthn MakeCredential extensions: {:?}",
            response.authenticator_data.extensions
        );

        let credential: Ctap2PublicKeyCredentialDescriptor =
            (&response.authenticator_data).try_into().unwrap();

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
        let hmac_or_prf: GetAssertionHmacOrPrfInput = GetAssertionHmacOrPrfInput::Prf(PrfInput {
            eval,
            eval_by_credential,
        });
        run_success_test(
            &mut channel,
            &credential,
            &challenge,
            hmac_or_prf,
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
        let hmac_or_prf: GetAssertionHmacOrPrfInput = GetAssertionHmacOrPrfInput::Prf(PrfInput {
            eval,
            eval_by_credential,
        });
        run_success_test(
            &mut channel,
            &credential,
            &challenge,
            hmac_or_prf,
            "eval and eval_by_credential",
        )
        .await;

        // Test 3: eval only
        let eval = Some(PRFValue {
            first: [1; 32],
            second: None,
        });

        let eval_by_credential = HashMap::new();
        let hmac_or_prf: GetAssertionHmacOrPrfInput = GetAssertionHmacOrPrfInput::Prf(PrfInput {
            eval,
            eval_by_credential,
        });
        run_success_test(
            &mut channel,
            &credential,
            &challenge,
            hmac_or_prf,
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
                second: None,
            },
        );
        let hmac_or_prf: GetAssertionHmacOrPrfInput = GetAssertionHmacOrPrfInput::Prf(PrfInput {
            eval,
            eval_by_credential,
        });
        run_success_test(
            &mut channel,
            &credential,
            &challenge,
            hmac_or_prf,
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
        let hmac_or_prf: GetAssertionHmacOrPrfInput = GetAssertionHmacOrPrfInput::Prf(PrfInput {
            eval,
            eval_by_credential,
        });
        run_success_test(
            &mut channel,
            &credential,
            &challenge,
            hmac_or_prf,
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
        let hmac_or_prf: GetAssertionHmacOrPrfInput = GetAssertionHmacOrPrfInput::Prf(PrfInput {
            eval,
            eval_by_credential,
        });
        run_success_test(
            &mut channel,
            &credential,
            &challenge,
            hmac_or_prf,
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
        let hmac_or_prf: GetAssertionHmacOrPrfInput = GetAssertionHmacOrPrfInput::Prf(PrfInput {
            eval,
            eval_by_credential,
        });
        run_failed_test(
            &mut channel,
            Some(&credential),
            &challenge,
            hmac_or_prf,
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
        let hmac_or_prf: GetAssertionHmacOrPrfInput = GetAssertionHmacOrPrfInput::Prf(PrfInput {
            eval,
            eval_by_credential,
        });
        run_failed_test(
            &mut channel,
            Some(&credential),
            &challenge,
            hmac_or_prf,
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
        let hmac_or_prf = GetAssertionHmacOrPrfInput::Prf(PrfInput {
            eval,
            eval_by_credential,
        });
        run_failed_test(
            &mut channel,
            None,
            &challenge,
            hmac_or_prf,
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
    hmac_or_prf: GetAssertionHmacOrPrfInput,
    printoutput: &str,
) {
    let get_assertion = GetAssertionRequest {
        relying_party_id: "example.org".to_owned(),
        hash: Vec::from(challenge),
        allow: vec![credential.clone()],
        user_verification: UserVerificationRequirement::Discouraged,
        extensions: GetAssertionRequestExtensions {
            hmac_or_prf: Some(hmac_or_prf),
            ..Default::default()
        },
        timeout: TIMEOUT,
    };

    let response = loop {
        match channel.webauthn_get_assertion(&get_assertion).await {
            Ok(response) => break Ok(response),
            Err(WebAuthnError::Ctap(ctap_error)) => {
                if ctap_error.is_retryable_user_error() {
                    println!("Oops, try again! Error: {}", ctap_error);
                    continue;
                }
                break Err(WebAuthnError::Ctap(ctap_error));
            }
            Err(err) => break Err(err),
        };
    }
    .unwrap();
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
    hmac_or_prf: GetAssertionHmacOrPrfInput,
    printoutput: &str,
    expected_error: WebAuthnError,
) {
    let get_assertion = GetAssertionRequest {
        relying_party_id: "example.org".to_owned(),
        hash: Vec::from(challenge),
        allow: credential.map(|x| vec![x.clone()]).unwrap_or_default(),
        user_verification: UserVerificationRequirement::Discouraged,
        extensions: GetAssertionRequestExtensions {
            hmac_or_prf: Some(hmac_or_prf),
            ..Default::default()
        },
        timeout: TIMEOUT,
    };

    let response: Result<(), libwebauthn::webauthn::Error> = loop {
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
