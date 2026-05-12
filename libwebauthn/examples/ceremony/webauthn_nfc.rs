use std::error::Error;

use libwebauthn::ops::webauthn::{
    GetAssertionRequest, JsonFormat, MakeCredentialRequest, RequestOrigin, SystemPublicSuffixList,
    WebAuthnIDL as _, WebAuthnIDLResponse as _,
};
use libwebauthn::transport::nfc::{get_nfc_device, is_nfc_available};
use libwebauthn::transport::{Channel as _, Device};
use libwebauthn::webauthn::WebAuthn;

#[path = "../common/mod.rs"]
mod common;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    common::setup_logging();

    if !is_nfc_available() {
        println!("No NFC-Reader found. NFC is not available on your system.");
        return Err("NFC not available".into());
    }

    let Some(mut device) = get_nfc_device().await? else {
        return Ok(());
    };
    println!("Selected NFC authenticator: {}", device);
    let mut channel = device.channel().await?;

    let request_origin: RequestOrigin = "https://example.org".try_into().expect("Invalid origin");
    let psl = SystemPublicSuffixList::auto().expect(
        "PSL not available; install the publicsuffix-list (or publicsuffix-list-dafsa) package, or pass an explicit path",
    );
    let make_credentials_request = MakeCredentialRequest::from_json(
        &request_origin,
        &psl,
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
    )
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

    let get_assertion = GetAssertionRequest::from_json(
        &request_origin,
        &psl,
        r#"
        {
            "challenge": "Y3JlZGVudGlhbHMtZm9yLWxpbnV4L2xpYndlYmF1dGhu",
            "timeout": 30000,
            "rpId": "example.org",
            "userVerification": "discouraged"
        }
        "#,
    )
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
