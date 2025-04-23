use std::collections::HashMap;
use std::convert::TryInto;
use std::error::Error;
use std::io::{self, Write};
use std::time::Duration;

use libwebauthn::transport::hid::channel::HidChannel;
use libwebauthn::UxUpdate;
use rand::{thread_rng, Rng};
use serde_bytes::ByteBuf;
use text_io::read;
use tokio::sync::mpsc::Receiver;
use tracing_subscriber::{self, EnvFilter};

use libwebauthn::ops::webauthn::{
    GetAssertionHmacOrPrfInput, GetAssertionHmacOrPrfOutput, GetAssertionRequest,
    GetAssertionRequestExtensions, PRFValue, UserVerificationRequirement,
};
use libwebauthn::pin::PinRequestReason;
use libwebauthn::proto::ctap2::{Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialType};
use libwebauthn::transport::hid::list_devices;
use libwebauthn::transport::Device;
use libwebauthn::webauthn::{Error as WebAuthnError, WebAuthn};

const TIMEOUT: Duration = Duration::from_secs(10);

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .without_time()
        .init();
}

async fn handle_updates(mut state_recv: Receiver<UxUpdate>) {
    while let Some(update) = state_recv.recv().await {
        match update {
            UxUpdate::PresenceRequired => println!("Please touch your device!"),
            UxUpdate::UvRetry { attempts_left } => {
                print!("UV failed.");
                if let Some(attempts_left) = attempts_left {
                    print!(" You have {attempts_left} attempts left.");
                }
            }
            UxUpdate::PinRequired(update) => {
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

    let argv: Vec<_> = std::env::args().collect();
    if argv.len() != 3 {
        println!("Usage: cargo run --example prf_test -- CREDENTIAL_ID FIRST_PRF_INPUT");
        println!();
        println!("CREDENTIAL_ID:   Credential ID to be used to sign against, as a hexstring (like 5830c80ae90f7865c631626573f1fdc7..)");
        println!(
            "FIRST_PRF_INPUT: PRF input to be used as a hexstring. Needs to be 32 bytes long!"
        );
        // println!("EXPECTED_RESULT: PRF output from the demo-webpage, that should be reproduced with this crate.");
        println!();
        println!("How to use:");
        println!("1. Go to https://demo.yubico.com/webauthn-developers");
        println!("2. Register there with PRF extension enabled, using your favorite browser");
        println!("3. Sign in, with FIRST_PRF_INPUT set");
        println!("4. Copy out the used hexstrings for credential_id and PRF input, and use them with this example");
        println!("5. Hope the outputs match");
        return Ok(());
    }
    let credential_id =
        hex::decode(argv[1].clone()).expect("CREDENTIAL_ID is not a valid hex code");
    let first_prf_input = hex::decode(argv[2].clone())
        .expect("FIRST_PRF_INPUT is not a valid hex code")
        .try_into()
        .expect("FIRST_PRF_INPUT is not exactly 32 bytes long");

    let devices = list_devices().await.unwrap();
    println!("Devices found: {:?}", devices);

    let challenge: [u8; 32] = thread_rng().gen();

    for mut device in devices {
        println!("Selected HID authenticator: {}", &device);
        let (mut channel, state_recv) = device.channel().await?;
        channel.wink(TIMEOUT).await?;

        tokio::spawn(handle_updates(state_recv));

        let credential = Ctap2PublicKeyCredentialDescriptor {
            r#type: Ctap2PublicKeyCredentialType::PublicKey,
            id: ByteBuf::from(credential_id.as_slice()),
            transports: None,
        };

        // eval only
        let eval = Some(PRFValue {
            first: first_prf_input,
            second: None,
        });

        let eval_by_credential = HashMap::new();
        let hmac_or_prf = GetAssertionHmacOrPrfInput::Prf {
            eval,
            eval_by_credential,
        };
        run_success_test(
            &mut channel,
            &credential,
            &challenge,
            hmac_or_prf,
            "PRF output: ",
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
        relying_party_id: "demo.yubico.com".to_owned(),
        hash: Vec::from(challenge),
        allow: vec![credential.clone()],
        user_verification: UserVerificationRequirement::Preferred,
        extensions: Some(GetAssertionRequestExtensions {
            hmac_or_prf,
            ..Default::default()
        }),
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
            assertion
                .authenticator_data
                .extensions
                .as_ref()
                .map(|e| match &e.hmac_or_prf {
                    GetAssertionHmacOrPrfOutput::None => String::from("ERROR: No PRF output"),
                    GetAssertionHmacOrPrfOutput::HmacGetSecret(..) =>
                        String::from("ERROR: Got HMAC instead of PRF output"),
                    GetAssertionHmacOrPrfOutput::Prf { enabled: _, result } =>
                        hex::encode(result.first),
                })
                .unwrap_or(String::from("ERROR: No extensions returned"))
        );
    }
}
