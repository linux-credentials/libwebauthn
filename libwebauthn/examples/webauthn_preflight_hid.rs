use std::convert::TryInto;
use std::error::Error;
use std::io::{self, Write};
use std::time::Duration;

use libwebauthn::UvUpdate;
use rand::{thread_rng, Rng};
use serde_bytes::ByteBuf;
use text_io::read;
use tokio::sync::broadcast::Receiver;
use tracing_subscriber::{self, EnvFilter};

use libwebauthn::ops::webauthn::{
    GetAssertionRequest, GetAssertionResponse, MakeCredentialRequest, ResidentKeyRequirement,
    UserVerificationRequirement,
};
use libwebauthn::pin::PinRequestReason;
use libwebauthn::proto::ctap2::{
    Ctap2CredentialType, Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialType, Ctap2PublicKeyCredentialUserEntity,
};
#[cfg(not(feature = "nfc"))]
use libwebauthn::transport::hid::list_devices;
#[cfg(feature = "nfc")]
use libwebauthn::transport::nfc::list_devices;
use libwebauthn::transport::{Channel, Device};
use libwebauthn::webauthn::{CtapError, Error as WebAuthnError, WebAuthn};

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

    println!("-------------------------------------------------------");
    println!("Run this test with RUST_LOG=libwebauthn::proto::ctap2::preflight=info to verify the outputs");
    println!("-------------------------------------------------------");
    let devices = list_devices().await.unwrap();
    println!("Devices found: {:?}", devices);

    let user_id: [u8; 32] = thread_rng().gen();

    for mut device in devices {
        println!("Selected HID authenticator: {}", &device);
        let mut channel = device.channel().await?;
        channel.wink(TIMEOUT).await?;

        let state_recv = channel.get_ux_update_receiver();
        tokio::spawn(handle_updates(state_recv));

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
        origin: "example.org".to_owned(),
        hash: Vec::from(challenge),
        relying_party: Ctap2PublicKeyCredentialRpEntity::new("example.org", "example.org"),
        user: Ctap2PublicKeyCredentialUserEntity::new(&user_id, "mario.rossi", "Mario Rossi"),
        resident_key: Some(ResidentKeyRequirement::Discouraged),
        user_verification: UserVerificationRequirement::Preferred,
        algorithms: vec![Ctap2CredentialType::default()],
        exclude: exclude_list,
        extensions: None,
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
    };
    response.map(|x| (&x.authenticator_data).try_into().unwrap())
}

async fn get_assertion_call(
    channel: &mut impl Channel,
    allow_list: Vec<Ctap2PublicKeyCredentialDescriptor>,
) -> Result<GetAssertionResponse, WebAuthnError> {
    let challenge: [u8; 32] = thread_rng().gen();
    let get_assertion = GetAssertionRequest {
        relying_party_id: "example.org".to_owned(),
        hash: Vec::from(challenge),
        allow: allow_list,
        user_verification: UserVerificationRequirement::Discouraged,
        extensions: None,
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
    };
    response
}

fn create_credential(id: &[u8]) -> Ctap2PublicKeyCredentialDescriptor {
    Ctap2PublicKeyCredentialDescriptor {
        r#type: Ctap2PublicKeyCredentialType::PublicKey,
        id: ByteBuf::from(id),
        transports: None,
    }
}
