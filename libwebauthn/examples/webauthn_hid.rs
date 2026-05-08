use std::convert::TryInto;
use std::error::Error;
use std::io::{self, Write};
use std::time::Duration;

use libwebauthn::UvUpdate;
use rand::{thread_rng, Rng};
use text_io::read;
use tokio::sync::broadcast::Receiver;
use tracing_subscriber::{self, EnvFilter};

use libwebauthn::ops::webauthn::{
    GetAssertionRequest, GetAssertionRequestExtensions, MakeCredentialRequest,
    ResidentKeyRequirement, UserVerificationRequirement,
};
use libwebauthn::pin::{PinNotSetReason, PinRequestReason};
use libwebauthn::proto::ctap2::{
    Ctap2CredentialType, Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialUserEntity,
};
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
            UvUpdate::PinNotSet(update) => {
                match update.reason {
                    PinNotSetReason::PinNotSet => println!("RP required a PIN, but your device has none set. Please set one now (this is NOT a RP-specific operation, but will require a PIN on your device from now on, if you continue. Leave the pini entry empty to cancel the operation.)"),
                    PinNotSetReason::PinTooShort => println!("The provided PIN was too short"),
                    PinNotSetReason::PinTooLong => println!("The provided PIN was too long"),
                    PinNotSetReason::PinPolicyViolation => println!("The provided PIN violated the pin policy set on the device."),
                }
                print!("PIN: Please set a new PIN for your device: ");
                io::stdout().flush().unwrap();
                let pin_raw: String = read!("{}\n");

                if pin_raw.is_empty() {
                    println!("PIN: No PIN provided, cancelling operation.");
                    update.cancel();
                } else {
                    let _ = update.set_pin(&pin_raw);
                    println!();
                }
            }
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

    for mut device in devices {
        println!("Selected HID authenticator: {}", &device);
        let mut channel = device.channel().await?;
        channel.wink(TIMEOUT).await?;

        // Ask user what kind of request should be issued
        let user_verification = {
            print!("Do you want to require user verification in the request? [y/N]: ");
            io::stdout().flush().expect("Failed to flush stdout!");
            let input: String = read!("{}\n");
            if input.trim() == "y" || input.trim() == "Y" {
                UserVerificationRequirement::Required
            } else {
                UserVerificationRequirement::Preferred
            }
        };

        // Make Credentials ceremony
        let make_credentials_request = MakeCredentialRequest {
            challenge: Vec::from(challenge),
            origin: "example.org".to_owned(),
            cross_origin: None,
            relying_party: Ctap2PublicKeyCredentialRpEntity::new("example.org", "example.org"),
            user: Ctap2PublicKeyCredentialUserEntity::new(&user_id, "mario.rossi", "Mario Rossi"),
            resident_key: Some(ResidentKeyRequirement::Discouraged),
            user_verification,
            algorithms: vec![Ctap2CredentialType::default()],
            exclude: None,
            extensions: None,
            timeout: TIMEOUT,
        };

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

        let credential: Ctap2PublicKeyCredentialDescriptor =
            (&response.authenticator_data).try_into().unwrap();
        let get_assertion = GetAssertionRequest {
            relying_party_id: "example.org".to_owned(),
            challenge: Vec::from(challenge),
            origin: "example.org".to_string(),
            cross_origin: None,
            allow: vec![credential],
            user_verification: UserVerificationRequirement::Discouraged,
            extensions: Some(GetAssertionRequestExtensions::default()),
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
        println!("WebAuthn GetAssertion response: {:?}", response);
    }

    Ok(())
}
