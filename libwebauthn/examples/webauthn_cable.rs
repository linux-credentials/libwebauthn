use std::error::Error;
use std::time::Duration;

use libwebauthn::transport::cable::channel::CableChannel;
use libwebauthn::transport::cable::known_devices::{
    CableKnownDeviceInfoStore, EphemeralDeviceInfoStore,
};
use libwebauthn::transport::cable::qr_code_device::{CableQrCodeDevice, QrCodeOperationHint};
use qrcode::render::unicode;
use qrcode::QrCode;
use rand::{thread_rng, Rng};
use tracing_subscriber::{self, EnvFilter};

use libwebauthn::ops::webauthn::{
    GetAssertionRequest, MakeCredentialRequest, UserVerificationRequirement,
};
use libwebauthn::pin::{UvProvider, StdinPromptPinProvider};
use libwebauthn::proto::ctap2::{
    Ctap2CredentialType, Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialUserEntity,
};
use libwebauthn::transport::Device;
use libwebauthn::webauthn::{Error as WebAuthnError, WebAuthn};

const TIMEOUT: Duration = Duration::from_secs(10);

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .without_time()
        .init();
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    setup_logging();

    let _device_info_store: Box<dyn CableKnownDeviceInfoStore> =
        Box::new(EphemeralDeviceInfoStore::default());

    // Create QR code
    let mut device: CableQrCodeDevice<'_> =
        CableQrCodeDevice::new_transient(QrCodeOperationHint::MakeCredential);

    println!("Created QR code, awaiting for advertisement.");
    let qr_code = QrCode::new(device.qr_code.to_string()).unwrap();
    let image = qr_code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();
    println!("{}", image);

    // Connect to a known device
    let mut channel: CableChannel = device.channel().await.unwrap();
    println!("Tunnel established {:?}", channel);

    let user_id: [u8; 32] = thread_rng().gen();
    let challenge: [u8; 32] = thread_rng().gen();

    let pin_provider: Box<dyn UvProvider> = Box::new(StdinPromptPinProvider::new());

    // Make Credentials ceremony
    let make_credentials_request = MakeCredentialRequest {
        origin: "example.org".to_owned(),
        hash: Vec::from(challenge),
        relying_party: Ctap2PublicKeyCredentialRpEntity::new("example.org", "example.org"),
        user: Ctap2PublicKeyCredentialUserEntity::new(&user_id, "mario.rossi", "Mario Rossi"),
        require_resident_key: false,
        user_verification: UserVerificationRequirement::Preferred,
        algorithms: vec![Ctap2CredentialType::default()],
        exclude: None,
        extensions: None,
        timeout: TIMEOUT,
    };

    let response = loop {
        match channel
            .webauthn_make_credential(&make_credentials_request, &pin_provider)
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
        hash: Vec::from(challenge),
        allow: vec![credential],
        user_verification: UserVerificationRequirement::Discouraged,
        extensions: None,
        timeout: TIMEOUT,
    };

    // Create QR code
    let mut device: CableQrCodeDevice<'_> =
        CableQrCodeDevice::new_transient(QrCodeOperationHint::GetAssertionRequest);

    println!("Created QR code, awaiting for advertisement.");
    let qr_code = QrCode::new(device.qr_code.to_string()).unwrap();
    let image = qr_code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();
    println!("{}", image);

    // Connect to a known device
    let mut channel: CableChannel = device.channel().await.unwrap();
    println!("Tunnel established {:?}", channel);

    let response = loop {
        match channel
            .webauthn_get_assertion(&get_assertion, &pin_provider)
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
    println!("WebAuthn GetAssertion response: {:?}", response);

    Ok(())
}
