use std::convert::TryInto;
use std::error::Error;
use std::io::{self, Write};
use std::time::Duration;

use libwebauthn::UxUpdate;
use rand::{thread_rng, Rng};
use text_io::read;
use tokio::sync::mpsc::Receiver;
use tracing_subscriber::{self, EnvFilter};

use libwebauthn::ops::webauthn::{
    CredentialProtectionExtension, CredentialProtectionPolicy, GetAssertionHmacOrPrfInput,
    GetAssertionRequest, GetAssertionRequestExtensions, HMACGetSecretInput,
    MakeCredentialHmacOrPrfInput, MakeCredentialLargeBlobExtension, MakeCredentialRequest,
    MakeCredentialsRequestExtensions, ResidentKeyRequirement, UserVerificationRequirement,
};
use libwebauthn::pin::PinRequestReason;
use libwebauthn::proto::ctap2::{
    Ctap2CredentialType, Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialUserEntity,
};
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

    let devices = list_devices().await.unwrap();
    println!("Devices found: {:?}", devices);

    let user_id: [u8; 32] = thread_rng().gen();
    let challenge: [u8; 32] = thread_rng().gen();

    let extensions = MakeCredentialsRequestExtensions {
        cred_protect: Some(CredentialProtectionExtension {
            policy: CredentialProtectionPolicy::UserVerificationRequired,
            enforce_policy: true,
        }),
        cred_blob: Some(r"My own little blob".into()),
        large_blob: MakeCredentialLargeBlobExtension::None,
        min_pin_length: Some(true),
        hmac_or_prf: MakeCredentialHmacOrPrfInput::HmacGetSecret,
        cred_props: Some(true),
    };

    for mut device in devices {
        println!("Selected HID authenticator: {}", &device);
        let (mut channel, state_recv) = device.channel().await?;
        channel.wink(TIMEOUT).await?;

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
        // println!("WebAuthn MakeCredential response: {:?}", response);
        println!(
            "WebAuthn MakeCredential extensions: {:?}",
            response.authenticator_data.extensions
        );

        let credential: Ctap2PublicKeyCredentialDescriptor =
            (&response.authenticator_data).try_into().unwrap();
        let get_assertion = GetAssertionRequest {
            relying_party_id: "example.org".to_owned(),
            hash: Vec::from(challenge),
            allow: vec![credential],
            user_verification: UserVerificationRequirement::Discouraged,
            extensions: Some(GetAssertionRequestExtensions {
                cred_blob: Some(true),
                hmac_or_prf: GetAssertionHmacOrPrfInput::HmacGetSecret(HMACGetSecretInput {
                    salt1: [1; 32],
                    salt2: None,
                }),
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
        // println!("WebAuthn GetAssertion response: {:?}", response);
        println!(
            "WebAuthn GetAssertion extensions: {:?}",
            response.assertions[0].authenticator_data.extensions
        );
        let blob = if let Some(ext) = &response.assertions[0].authenticator_data.extensions {
            ext.cred_blob
                .clone()
                .map(|x| String::from_utf8_lossy(&x).to_string())
        } else {
            None
        };
        println!("Credential blob: {blob:?}");
    }

    Ok(())
}
