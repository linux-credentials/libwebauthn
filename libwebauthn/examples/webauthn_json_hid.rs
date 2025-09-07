use std::error::Error;
use std::io::{self, Write};
use std::time::Duration;

use libwebauthn::UvUpdate;
use text_io::read;
use tokio::sync::broadcast::Receiver;
use tracing_subscriber::{self, EnvFilter};

use libwebauthn::ops::webauthn::{
    GetAssertionRequest, MakeCredentialRequest, RelyingPartyId, WebAuthnIDL as _,
};
use libwebauthn::pin::PinRequestReason;
use libwebauthn::transport::hid::list_devices;
use libwebauthn::transport::{Channel as _, Device};
use libwebauthn::webauthn::{Error as WebAuthnError, WebAuthn};

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

    for mut device in devices {
        println!("Selected HID authenticator: {}", &device);
        let mut channel = device.channel().await?;
        channel.wink(TIMEOUT).await?;

        // Relying
        let rpid = RelyingPartyId("example.org".to_owned());
        let request_json = r#"
                {
                    "rp": {
                        "id": "example.org",
                        "name": "Example Relying Party"
                    },
                    "user": {
                        "id": "MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2Nzg",
                        "name": "Mario Rossi",
                        "displayName": "Mario Rossi"
                    },
                    "challenge": "MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2Nzg",
                    "pubKeyCredParams": [
                        {"type": "public-key", "alg": -7}
                    ],
                    "timeout": 60000,
                    "excludeCredentials": [],
                    "authenticatorSelection": {
                        "residentKey": "discouraged",
                        "userVerification": "preferred"
                    },
                    "attestation": "none"
                }
                "#;
        let make_credentials_request: MakeCredentialRequest =
            MakeCredentialRequest::from_json(&rpid, request_json)
                .expect("Failed to parse request JSON");
        println!(
            "WebAuthn MakeCredential request: {:?}",
            make_credentials_request
        );

        let state_recv = channel.get_ux_update_receiver();
        tokio::spawn(handle_updates(state_recv));

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
        println!("WebAuthn MakeCredential response: {:?}", response);

        let request_json = r#"
                {
                    "challenge": "Y3JlZGVudGlhbHMtZm9yLWxpbnV4L2xpYndlYmF1dGhu",
                    "timeout": 30000,
                    "rpId": "example.org",
                    "userVerification": "discouraged"
                }
                "#;
        let get_assertion: GetAssertionRequest =
            GetAssertionRequest::from_json(&rpid, request_json)
                .expect("Failed to parse request JSON");
        println!("WebAuthn GetAssertion request: {:?}", get_assertion);

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
        println!("WebAuthn GetAssertion response: {:?}", response);
    }

    Ok(())
}
