//! caBLE / CTAP 2.3 hybrid: the QR advertises both the WebSocket tunnel and
//! the BLE L2CAP channel so the authenticator can pick either one. Transient
//! MakeCredential only.
use std::error::Error;

use libwebauthn::transport::cable::is_available;
use libwebauthn::transport::cable::qr_code_device::{
    CableQrCodeDevice, CableTransports, QrCodeOperationHint,
};
use qrcode::render::unicode;
use qrcode::QrCode;

use libwebauthn::ops::webauthn::{
    DatFilePublicSuffixList, JsonFormat, MakeCredentialRequest, RequestOrigin, WebAuthnIDL as _,
    WebAuthnIDLResponse as _,
};
use libwebauthn::transport::{Channel as _, Device};
use libwebauthn::webauthn::WebAuthn;

#[path = "../common/mod.rs"]
mod common;

const MAKE_CREDENTIAL_REQUEST: &str = r#"
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
    "timeout": 120000,
    "excludeCredentials": [],
    "authenticatorSelection": {
        "residentKey": "discouraged",
        "userVerification": "preferred"
    },
    "attestation": "none"
}
"#;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    common::setup_logging();

    if !is_available().await {
        eprintln!("No Bluetooth adapter found. Cable/Hybrid transport is unavailable.");
        return Err("Cable transport not available".into());
    }

    let request_origin: RequestOrigin = "https://example.org".try_into().expect("Invalid origin");
    let psl = DatFilePublicSuffixList::from_system_file().expect(
        "PSL not available; install the publicsuffix-list package or pass an explicit path",
    );

    let mut device: CableQrCodeDevice = CableQrCodeDevice::new_transient(
        QrCodeOperationHint::MakeCredential,
        CableTransports::CloudAssistedOrLocal,
    )?;

    println!("Created QR code, awaiting for advertisement.");
    let qr_code = QrCode::new(device.qr_code.to_string()).unwrap();
    let image = qr_code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();
    println!("{}", image);

    let mut channel = device.channel().await.unwrap();
    println!("Channel established {:?}", channel);

    let state_recv = channel.get_ux_update_receiver();
    tokio::spawn(common::handle_cable_updates(state_recv));

    let request = MakeCredentialRequest::from_json(&request_origin, &psl, MAKE_CREDENTIAL_REQUEST)
        .expect("Failed to parse request JSON");

    let response = retry_user_errors!(channel.webauthn_make_credential(&request)).unwrap();
    let response_json = response
        .to_json_string(&request, JsonFormat::Prettified)
        .expect("Failed to serialize MakeCredential response");
    println!("WebAuthn MakeCredential response (JSON):\n{response_json}");

    Ok(())
}
