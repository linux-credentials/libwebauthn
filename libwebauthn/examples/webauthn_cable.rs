use std::error::Error;
use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;

use libwebauthn::pin::PinRequestReason;
use libwebauthn::transport::cable::channel::{CableUpdate, CableUxUpdate};
use libwebauthn::transport::cable::known_devices::{
    CableKnownDevice, ClientPayloadHint, EphemeralDeviceInfoStore,
};
use libwebauthn::transport::cable::qr_code_device::{CableQrCodeDevice, QrCodeOperationHint};
use libwebauthn::UvUpdate;
use qrcode::render::unicode;
use qrcode::QrCode;
use rand::{thread_rng, Rng};
use text_io::read;
use tokio::sync::broadcast::Receiver;
use tokio::time::sleep;
use tracing_subscriber::{self, EnvFilter};

use libwebauthn::ops::webauthn::{
    GetAssertionRequest, GetAssertionRequestExtensions, MakeCredentialRequest,
    ResidentKeyRequirement, UserVerificationRequirement,
};
use libwebauthn::proto::ctap2::{
    Ctap2CredentialType, Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialUserEntity,
};
use libwebauthn::transport::{Channel as _, Device};
use libwebauthn::webauthn::{Error as WebAuthnError, WebAuthn};

const TIMEOUT: Duration = Duration::from_secs(120);

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .without_time()
        .init();
}

async fn handle_updates(mut state_recv: Receiver<CableUxUpdate>) {
    while let Ok(update) = state_recv.recv().await {
        match update {
            CableUxUpdate::UvUpdate(uv_update) => match uv_update {
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
            },
            CableUxUpdate::CableUpdate(cable_update) => match cable_update {
                CableUpdate::ProximityCheck => println!("Proximity check in progress..."),
                CableUpdate::Connecting => println!("Connecting to the device..."),
                CableUpdate::Authenticating => println!("Authenticating with the device..."),
                CableUpdate::Connected => println!("Tunnel established successfully!"),
                CableUpdate::Error(err) => println!("Error during connection: {}", err),
            },
        }
    }
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    setup_logging();

    let device_info_store = Arc::new(EphemeralDeviceInfoStore::default());
    let user_id: [u8; 32] = thread_rng().gen();
    let challenge: [u8; 32] = thread_rng().gen();

    let credential: Ctap2PublicKeyCredentialDescriptor = {
        // Create QR code
        let mut device: CableQrCodeDevice = CableQrCodeDevice::new_persistent(
            QrCodeOperationHint::MakeCredential,
            device_info_store.clone(),
        );

        println!("Created QR code, awaiting for advertisement.");
        let qr_code = QrCode::new(device.qr_code.to_string()).unwrap();
        let image = qr_code
            .render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Light)
            .light_color(unicode::Dense1x2::Dark)
            .build();
        println!("{}", image);

        // Connect to a known device
        let mut channel = device.channel().await.unwrap();
        println!("Tunnel established {:?}", channel);

        let state_recv = channel.get_ux_update_receiver();
        tokio::spawn(handle_updates(state_recv));

        // Make Credentials ceremony
        let make_credentials_request = MakeCredentialRequest {
            origin: "example.org".to_owned(),
            hash: Vec::from(challenge),
            relying_party: Ctap2PublicKeyCredentialRpEntity::new("example.org", "example.org"),
            user: Ctap2PublicKeyCredentialUserEntity::new(&user_id, "mario.rossi", "Mario Rossi"),
            resident_key: Some(ResidentKeyRequirement::Discouraged),
            user_verification: UserVerificationRequirement::Preferred,
            algorithms: vec![Ctap2CredentialType::default()],
            exclude: None,
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
        }
        .unwrap();
        println!("WebAuthn MakeCredential response: {:?}", response);

        (&response.authenticator_data).try_into().unwrap()
    };

    println!("Waiting for 5 seconds before contacting the device...");
    sleep(Duration::from_secs(5)).await;

    let get_assertion = GetAssertionRequest {
        relying_party_id: "example.org".to_owned(),
        hash: Vec::from(challenge),
        allow: vec![credential],
        user_verification: UserVerificationRequirement::Discouraged,
        extensions: Some(GetAssertionRequestExtensions::default()),
        timeout: TIMEOUT,
    };

    let all_devices = device_info_store.list_all().await;
    let (_known_device_id, known_device_info) =
        all_devices.first().expect("No known devices found");

    let mut known_device: CableKnownDevice = CableKnownDevice::new(
        ClientPayloadHint::GetAssertion,
        known_device_info,
        device_info_store.clone(),
    )
    .await
    .unwrap();

    // Connect to a known device
    let mut channel = known_device.channel().await.unwrap();
    println!("Tunnel established {:?}", channel);

    let state_recv = channel.get_ux_update_receiver();
    tokio::spawn(handle_updates(state_recv));

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

    Ok(())
}
