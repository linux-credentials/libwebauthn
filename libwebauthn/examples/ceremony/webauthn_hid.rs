use std::error::Error;
use std::time::Duration;

use libwebauthn::ops::webauthn::{
    GetAssertionRequest, JsonFormat, MakeCredentialRequest, RequestOrigin, SystemPublicSuffixList,
    WebAuthnIDL as _, WebAuthnIDLResponse as _,
};
use libwebauthn::proto::ctap2::Ctap2PublicKeyCredentialDescriptor;
use libwebauthn::transport::hid::list_devices;
use libwebauthn::transport::{Channel as _, Device};
use libwebauthn::webauthn::WebAuthn;

#[path = "../common/mod.rs"]
mod common;

const TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    common::setup_logging();

    let devices = list_devices().await.unwrap();
    println!("Devices found: {:?}", devices);

    for mut device in devices {
        println!("Selected HID authenticator: {}", &device);
        let mut channel = device.channel().await?;
        channel.wink(TIMEOUT).await?;

        let request_origin: RequestOrigin =
            "https://example.org".try_into().expect("Invalid origin");
        let psl = SystemPublicSuffixList::auto().expect(
            "PSL not available; install the publicsuffix-list (or publicsuffix-list-dafsa) package, or pass an explicit path",
        );
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
            MakeCredentialRequest::from_json(&request_origin, &psl, request_json)
                .expect("Failed to parse request JSON");
        println!(
            "WebAuthn MakeCredential request: {:?}",
            make_credentials_request
        );

        let state_recv = channel.get_ux_update_receiver();
        tokio::spawn(common::handle_uv_updates(state_recv));

        let response =
            retry_user_errors!(channel.webauthn_make_credential(&make_credentials_request))
                .unwrap();
        println!("WebAuthn MakeCredential response: {:?}", response);

        match response.to_json_string(&make_credentials_request, JsonFormat::Prettified) {
            Ok(response_json) => {
                println!(
                    "WebAuthn MakeCredential response (JSON):\n{}",
                    response_json
                );
            }
            Err(e) => {
                eprintln!("Failed to serialize MakeCredential response: {:?}", e);
            }
        }

        let cred: Ctap2PublicKeyCredentialDescriptor =
            (&response.authenticator_data).try_into().unwrap();
        let cred_id_b64 = base64_url::encode(cred.id.as_ref());
        let request_json = format!(
            r#"
                {{
                    "challenge": "Y3JlZGVudGlhbHMtZm9yLWxpbnV4L2xpYndlYmF1dGhu",
                    "timeout": 30000,
                    "rpId": "example.org",
                    "userVerification": "discouraged",
                    "allowCredentials": [
                        {{"id": "{cred_id_b64}", "type": "public-key", "transports": ["usb"]}}
                    ]
                }}
                "#
        );
        let get_assertion: GetAssertionRequest =
            GetAssertionRequest::from_json(&request_origin, &psl, &request_json)
                .expect("Failed to parse request JSON");
        println!("WebAuthn GetAssertion request: {:?}", get_assertion);

        let response = retry_user_errors!(channel.webauthn_get_assertion(&get_assertion)).unwrap();
        println!("WebAuthn GetAssertion response: {:?}", response);

        for assertion in &response.assertions {
            match assertion.to_json_string(&get_assertion, JsonFormat::Prettified) {
                Ok(assertion_json) => {
                    println!("WebAuthn GetAssertion response (JSON):\n{}", assertion_json);
                }
                Err(e) => {
                    eprintln!("Failed to serialize GetAssertion response: {:?}", e);
                }
            }
        }
    }

    Ok(())
}
