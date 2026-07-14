//! HID make-credential with related origins enabled.
//!
//! The bundled reqwest-backed [`ReqwestRelatedOriginsSource`] fetches
//! `https://<rp.id>/.well-known/webauthn` when the request's rp.id is not a
//! registrable suffix of the caller origin. This demo is same-origin
//! (`example.org`), so the source is wired but the fetch is not triggered. It
//! fires when rp.id and the origin sit on different registrable domains, with
//! the RP listing the caller origin in its well-known document.

use std::error::Error;
use std::time::Duration;

use libwebauthn::ops::webauthn::{
    JsonFormat, MakeCredentialRequest, MaxRegistrableLabels, OriginValidation, RelatedOrigins,
    RequestOrigin, RequestSettings, ReqwestRelatedOriginsSource, SystemPublicSuffixList,
    WebAuthnIDLResponse as _,
};
use libwebauthn::transport::hid::list_devices;
use libwebauthn::transport::{Channel as _, ChannelSettings, Device};
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
        println!("Selected HID authenticator: {}", device);
        let mut channel = device.channel(ChannelSettings::default()).await?;
        channel.wink(TIMEOUT).await?;

        let request_origin: RequestOrigin =
            "https://example.org".try_into().expect("Invalid origin");
        let psl = SystemPublicSuffixList::auto().expect(
            "PSL not available; install the publicsuffix-list (or publicsuffix-list-dafsa) package, or pass an explicit path",
        );
        let related_origins = ReqwestRelatedOriginsSource::new()?;
        let settings = RequestSettings {
            origin: OriginValidation::Validate {
                public_suffix_list: &psl,
                related_origins: RelatedOrigins::Enabled {
                    source: &related_origins,
                    max_labels: MaxRegistrableLabels::default(),
                },
            },
        };
        let request_json = r#"
            {
                "rp": { "id": "example.org", "name": "Example Relying Party" },
                "user": {
                    "id": "MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2Nzg",
                    "name": "alice",
                    "displayName": "Alice"
                },
                "challenge": "MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2Nzg",
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
                "timeout": 60000,
                "excludeCredentials": [],
                "authenticatorSelection": { "residentKey": "discouraged", "userVerification": "preferred" },
                "attestation": "none"
            }
            "#;
        let request = MakeCredentialRequest::prepare(&request_origin, request_json, &settings)
            .await
            .expect("Failed to parse request JSON");

        let state_recv = channel.get_ux_update_receiver();
        tokio::spawn(common::handle_uv_updates(state_recv));

        let response = retry_user_errors!(channel.webauthn_make_credential(&request)).unwrap();
        let response_json = response
            .to_json_string(&request, JsonFormat::Prettified)
            .expect("Failed to serialize MakeCredential response");
        println!("WebAuthn MakeCredential response (JSON):\n{response_json}");
    }

    Ok(())
}
