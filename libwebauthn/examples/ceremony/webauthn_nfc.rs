use std::error::Error;

use libwebauthn::ops::webauthn::{
    GetAssertionRequest, JsonFormat, MakeCredentialRequest, OriginValidation, RelatedOrigins,
    RequestOrigin, RequestSettings, SystemPublicSuffixList, WebAuthnIDLResponse as _,
};
use libwebauthn::transport::nfc::NfcDeviceSliceExt;
use libwebauthn::transport::{hid, nfc, Channel as _, ChannelSettings, Device};
use libwebauthn::webauthn::WebAuthn;

#[path = "../common/mod.rs"]
mod common;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    common::setup_logging();

    if !nfc::is_nfc_available() {
        println!("No NFC-Reader found. NFC is not available on your system.");
        return Err("NFC not available".into());
    }

    // A USB key's CCID interface also shows up as a PC/SC reader, so drop the
    // NFC entries that duplicate a connected HID key.
    let hid_devices = hid::list_devices().await.unwrap_or_default();
    let nfc_devices = nfc::list_devices().await;
    let discovered = nfc_devices.len();
    let nfc_devices = nfc_devices.without_hid_duplicates(&hid_devices);
    println!(
        "Discovered {discovered} NFC device(s); dropped {} that duplicate a connected HID key.",
        discovered - nfc_devices.len()
    );

    // Unfiltered, so keep the first survivor that opens a FIDO channel.
    let mut selected = None;
    for mut device in nfc_devices {
        match device.channel(ChannelSettings::default()).await {
            Ok(channel) => {
                println!("Selected NFC authenticator: {device}");
                selected = Some(channel);
                break;
            }
            Err(error) => println!("Skipping NFC reader (no FIDO applet): {error}"),
        }
    }
    let Some(mut channel) = selected else {
        println!("No FIDO NFC authenticator found after de-duplication.");
        return Ok(());
    };

    let request_origin: RequestOrigin = "https://example.org".try_into().expect("Invalid origin");
    let psl = SystemPublicSuffixList::auto().expect(
        "PSL not available; install the publicsuffix-list (or publicsuffix-list-dafsa) package, or pass an explicit path",
    );
    let settings = RequestSettings {
        origin: OriginValidation::Validate {
            public_suffix_list: &psl,
            related_origins: RelatedOrigins::Disabled,
        },
    };
    let make_credentials_request = MakeCredentialRequest::prepare(
        &request_origin,
        r#"
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
        "#,
        &settings,
    )
    .await
    .expect("Failed to parse request JSON");
    println!(
        "WebAuthn MakeCredential request: {:?}",
        make_credentials_request
    );

    let state_recv = channel.get_ux_update_receiver();
    tokio::spawn(common::handle_uv_updates(state_recv));

    let response =
        retry_user_errors!(channel.webauthn_make_credential(&make_credentials_request)).unwrap();
    let response_json = response
        .to_json_string(&make_credentials_request, JsonFormat::Prettified)
        .expect("Failed to serialize MakeCredential response");
    println!("WebAuthn MakeCredential response (JSON):\n{response_json}");

    let get_assertion = GetAssertionRequest::prepare(
        &request_origin,
        r#"
        {
            "challenge": "Y3JlZGVudGlhbHMtZm9yLWxpbnV4L2xpYndlYmF1dGhu",
            "timeout": 30000,
            "rpId": "example.org",
            "userVerification": "discouraged"
        }
        "#,
        &settings,
    )
    .await
    .expect("Failed to parse request JSON");
    println!("WebAuthn GetAssertion request: {:?}", get_assertion);

    let response = retry_user_errors!(channel.webauthn_get_assertion(&get_assertion)).unwrap();
    for assertion in &response.assertions {
        let assertion_json = assertion
            .to_json_string(&get_assertion, JsonFormat::Prettified)
            .expect("Failed to serialize GetAssertion response");
        println!("WebAuthn GetAssertion response (JSON):\n{assertion_json}");
    }

    Ok(())
}
