use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use libwebauthn::transport::cable::is_available;
use libwebauthn::transport::cable::known_devices::{
    CableKnownDevice, ClientPayloadHint, EphemeralDeviceInfoStore,
};
use libwebauthn::transport::cable::qr_code_device::{
    CableQrCodeDevice, CableTransports, QrCodeOperationHint,
};
use qrcode::render::unicode;
use qrcode::QrCode;
use tokio::time::sleep;

use libwebauthn::ops::webauthn::{
    DatFilePublicSuffixList, GetAssertionRequest, JsonFormat, MakeCredentialRequest, RequestOrigin,
    WebAuthnIDL as _, WebAuthnIDLResponse as _,
};
use libwebauthn::transport::cable::channel::CableChannel;
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

const GET_ASSERTION_REQUEST: &str = r#"
{
    "challenge": "Y3JlZGVudGlhbHMtZm9yLWxpbnV4L2xpYndlYmF1dGhu",
    "timeout": 120000,
    "rpId": "example.org",
    "userVerification": "discouraged"
}
"#;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    common::setup_logging();

    if !is_available().await {
        eprintln!("No Bluetooth adapter found. Cable/Hybrid transport is unavailable.");
        return Err("Cable transport not available".into());
    }

    let device_info_store = Arc::new(EphemeralDeviceInfoStore::default());
    let request_origin: RequestOrigin = "https://example.org".try_into().expect("Invalid origin");
    let psl = DatFilePublicSuffixList::from_system_file().expect(
        "PSL not available; install the publicsuffix-list package or pass an explicit path",
    );

    {
        let mut device: CableQrCodeDevice = CableQrCodeDevice::new_persistent(
            QrCodeOperationHint::MakeCredential,
            device_info_store.clone(),
            CableTransports::CloudAssistedOnly,
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

        let request =
            MakeCredentialRequest::from_json(&request_origin, &psl, MAKE_CREDENTIAL_REQUEST)
                .expect("Failed to parse request JSON");

        let response = retry_user_errors!(channel.webauthn_make_credential(&request)).unwrap();
        let response_json = response
            .to_json_string(&request, JsonFormat::Prettified)
            .expect("Failed to serialize MakeCredential response");
        println!("WebAuthn MakeCredential response (JSON):\n{response_json}");
    }

    println!("Waiting for 5 seconds before contacting the device...");
    sleep(Duration::from_secs(5)).await;

    // Second leg: prefer state-assisted reconnection if the peer offered
    // linking info, otherwise fall back to a fresh QR. Many authenticators
    // don't send linking info, so the fallback is the common path.
    let all_devices = device_info_store.list_all().await;
    if let Some((_, known_device_info)) = all_devices.first() {
        println!("Reconnecting state-assisted to known device...");
        let mut known_device: CableKnownDevice = CableKnownDevice::new(
            ClientPayloadHint::GetAssertion,
            known_device_info,
            device_info_store.clone(),
        )
        .await
        .unwrap();
        let mut channel = known_device.channel().await.unwrap();
        println!("Channel established {:?}", channel);
        run_get_assertion(&mut channel, &request_origin, &psl).await?;
    } else {
        println!("No known devices (peer did not offer linking). Falling back to QR.");
        let mut device: CableQrCodeDevice = CableQrCodeDevice::new_persistent(
            QrCodeOperationHint::GetAssertionRequest,
            device_info_store.clone(),
            CableTransports::CloudAssistedOnly,
        )?;
        let qr_code = QrCode::new(device.qr_code.to_string()).unwrap();
        let image = qr_code
            .render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Light)
            .light_color(unicode::Dense1x2::Dark)
            .build();
        println!("{}", image);
        let mut channel = device.channel().await.unwrap();
        println!("Channel established {:?}", channel);
        run_get_assertion(&mut channel, &request_origin, &psl).await?;
    }

    Ok(())
}

async fn run_get_assertion(
    channel: &mut CableChannel,
    request_origin: &RequestOrigin,
    psl: &DatFilePublicSuffixList,
) -> Result<(), Box<dyn Error>> {
    let state_recv = channel.get_ux_update_receiver();
    tokio::spawn(common::handle_cable_updates(state_recv));

    let request = GetAssertionRequest::from_json(request_origin, psl, GET_ASSERTION_REQUEST)
        .expect("Failed to parse request JSON");
    let response = retry_user_errors!(channel.webauthn_get_assertion(&request)).unwrap();
    for assertion in &response.assertions {
        let assertion_json = assertion
            .to_json_string(&request, JsonFormat::Prettified)
            .expect("Failed to serialize GetAssertion response");
        println!("WebAuthn GetAssertion response (JSON):\n{assertion_json}");
    }
    Ok(())
}
