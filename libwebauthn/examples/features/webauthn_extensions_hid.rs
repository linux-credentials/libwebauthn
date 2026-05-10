use std::convert::TryInto;
use std::error::Error;
use std::time::Duration;

use rand::{thread_rng, Rng};

use libwebauthn::ops::webauthn::{
    CredentialProtectionExtension, CredentialProtectionPolicy, GetAssertionRequest,
    GetAssertionRequestExtensions, MakeCredentialRequest, MakeCredentialsRequestExtensions,
    PRFValue, PrfInput, ResidentKeyRequirement, UserVerificationRequirement,
};
use libwebauthn::proto::ctap2::{
    Ctap2CredentialType, Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialUserEntity,
};
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

    let user_id: [u8; 32] = thread_rng().gen();
    let challenge: [u8; 32] = thread_rng().gen();

    let extensions = MakeCredentialsRequestExtensions {
        cred_protect: Some(CredentialProtectionExtension {
            policy: CredentialProtectionPolicy::UserVerificationRequired,
            enforce_policy: true,
        }),
        cred_blob: Some("My own little blob".as_bytes().into()),
        large_blob: None,
        min_pin_length: Some(true),
        hmac_create_secret: Some(true),
        prf: None,
        cred_props: Some(true),
        appid_exclude: None,
    };

    for mut device in devices {
        println!("Selected HID authenticator: {}", &device);
        let mut channel = device.channel().await?;
        channel.wink(TIMEOUT).await?;

        let state_recv = channel.get_ux_update_receiver();
        tokio::spawn(common::handle_uv_updates(state_recv));

        let make_credentials_request = MakeCredentialRequest {
            challenge: Vec::from(challenge),
            origin: "example.org".to_owned(),
            top_origin: None,
            relying_party: Ctap2PublicKeyCredentialRpEntity::new("example.org", "example.org"),
            user: Ctap2PublicKeyCredentialUserEntity::new(&user_id, "mario.rossi", "Mario Rossi"),
            resident_key: Some(ResidentKeyRequirement::Required),
            user_verification: UserVerificationRequirement::Preferred,
            algorithms: vec![Ctap2CredentialType::default()],
            exclude: None,
            extensions: Some(extensions.clone()),
            timeout: TIMEOUT,
        };

        let response =
            retry_user_errors!(channel.webauthn_make_credential(&make_credentials_request))
                .unwrap();
        println!(
            "WebAuthn MakeCredential extensions: {:?}",
            response.authenticator_data.extensions
        );

        let credential: Ctap2PublicKeyCredentialDescriptor =
            (&response.authenticator_data).try_into().unwrap();
        let get_assertion = GetAssertionRequest {
            relying_party_id: "example.org".to_owned(),
            challenge: Vec::from(challenge),
            origin: "example.org".to_string(),
            top_origin: None,
            allow: vec![credential],
            user_verification: UserVerificationRequirement::Discouraged,
            extensions: Some(GetAssertionRequestExtensions {
                cred_blob: true,
                prf: Some(PrfInput {
                    eval: Some(PRFValue {
                        first: [1; 32],
                        second: None,
                    }),
                    eval_by_credential: std::collections::HashMap::new(),
                }),
                ..Default::default()
            }),
            timeout: TIMEOUT,
        };

        let response = retry_user_errors!(channel.webauthn_get_assertion(&get_assertion)).unwrap();
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
