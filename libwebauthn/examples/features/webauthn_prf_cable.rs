//! PRF extension over caBLE/hybrid, against a phone authenticator that
//! advertises the `prf` extension in getInfo.
//!
//!   cargo run --example webauthn_prf_cable -- create
//!   cargo run --example webauthn_prf_cable -- get [credential-id]
//!
//! `create` registers a discoverable credential with PRF enabled and an eval
//! at creation, then prints the credential ID. `get` asserts with PRF eval
//! salts. When a credential ID is given, it is added to the allow list with an
//! evalByCredential entry.

use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;

use libwebauthn::ops::webauthn::{
    GetAssertionRequest, GetAssertionRequestExtensions, JsonFormat, MakeCredentialPrfInput,
    MakeCredentialRequest, MakeCredentialsRequestExtensions, PrfInput, PrfInputValue,
    ResidentKeyRequirement, UserVerificationRequirement, WebAuthnIDLResponse as _,
};
use libwebauthn::proto::ctap2::{
    Ctap2CredentialType, Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialType, Ctap2PublicKeyCredentialUserEntity,
};
use libwebauthn::transport::cable::channel::CableChannel;
use libwebauthn::transport::cable::is_available;
use libwebauthn::transport::cable::qr_code_device::{
    CableQrCodeDevice, CableTransports, QrCodeOperationHint,
};
use libwebauthn::transport::{Channel as _, ChannelSettings, Device};
use libwebauthn::webauthn::WebAuthn;
use qrcode::render::unicode;
use qrcode::QrCode;
use serde_bytes::ByteBuf;

#[path = "../common/mod.rs"]
mod common;

const TIMEOUT: Duration = Duration::from_secs(120);
const RP_ID: &str = "example.org";
const ORIGIN: &str = "https://example.org";

// Deterministic PRF inputs, so results can be cross-checked against another
// client holding the same credential.
const CREATE_EVAL_FIRST: &[u8] = b"example-prf-create-first";
const CREATE_EVAL_SECOND: &[u8] = b"example-prf-create-second";
const GET_EVAL_FIRST: &[u8] = b"example-prf-get-first";
const GET_EVAL_SECOND: &[u8] = b"example-prf-get-second";
const BY_CRED_FIRST: &[u8] = b"example-prf-bycred-first";
const BY_CRED_SECOND: &[u8] = b"example-prf-bycred-second";

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    common::setup_logging();

    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str);

    if !is_available().await {
        eprintln!("No Bluetooth adapter found. Cable/Hybrid transport is unavailable.");
        return Err("Cable transport not available".into());
    }

    match mode {
        Some("create") => create().await,
        Some("get") => get(args.get(2).map(String::as_str)).await,
        _ => {
            eprintln!("Usage: webauthn_prf_cable <create | get [credential-id-base64url]>");
            Err("missing or unknown subcommand".into())
        }
    }
}

async fn connect(
    hint: QrCodeOperationHint,
) -> Result<(CableQrCodeDevice, CableChannel), Box<dyn Error>> {
    let mut device: CableQrCodeDevice =
        CableQrCodeDevice::new_transient(hint, CableTransports::CloudAssistedOrLocal)?;

    println!("Created QR code, awaiting advertisement.");
    let qr_code = QrCode::new(device.qr_code.to_string()).unwrap();
    let image = qr_code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build();
    println!("{}", image);

    let channel = device.channel(ChannelSettings::default()).await?;
    println!("Channel established {:?}", channel);

    let state_recv = channel.get_ux_update_receiver();
    tokio::spawn(common::handle_cable_updates(state_recv));
    Ok((device, channel))
}

async fn create() -> Result<(), Box<dyn Error>> {
    let (_device, mut channel) = connect(QrCodeOperationHint::MakeCredential).await?;

    let extensions = MakeCredentialsRequestExtensions {
        prf: Some(MakeCredentialPrfInput {
            eval: Some(PrfInputValue {
                first: CREATE_EVAL_FIRST.to_vec(),
                second: Some(CREATE_EVAL_SECOND.to_vec()),
            }),
        }),
        ..Default::default()
    };

    let request = MakeCredentialRequest {
        challenge: vec![0x11; 32],
        origin: ORIGIN.to_owned(),
        top_origin: None,
        relying_party: Ctap2PublicKeyCredentialRpEntity::new(RP_ID, "Example Relying Party"),
        user: Ctap2PublicKeyCredentialUserEntity::new(&[0x42; 16], "alice", "Alice"),
        resident_key: Some(ResidentKeyRequirement::Required),
        user_verification: UserVerificationRequirement::Preferred,
        algorithms: vec![Ctap2CredentialType::default()],
        exclude: None,
        extensions: Some(extensions),
        attestation: None,
        timeout: TIMEOUT,
    };

    let response = retry_user_errors!(channel.webauthn_make_credential(&request)).unwrap();

    let response_json = response
        .to_json_string(&request, JsonFormat::Prettified)
        .expect("Failed to serialize MakeCredential response");
    println!("WebAuthn MakeCredential response (JSON):\n{response_json}");

    let credential: Ctap2PublicKeyCredentialDescriptor =
        (&response.authenticator_data).try_into().unwrap();
    println!(
        "\nCredential ID (base64url): {}",
        base64_url::encode(&credential.id)
    );
    println!("Next: run the `get` leg, e.g.");
    println!(
        "cargo run --example webauthn_prf_cable -- get {}",
        base64_url::encode(&credential.id)
    );
    Ok(())
}

async fn get(credential_id: Option<&str>) -> Result<(), Box<dyn Error>> {
    let (_device, mut channel) = connect(QrCodeOperationHint::GetAssertionRequest).await?;

    let mut eval_by_credential = HashMap::new();
    let allow = match credential_id {
        Some(encoded) => {
            eval_by_credential.insert(
                encoded.to_owned(),
                PrfInputValue {
                    first: BY_CRED_FIRST.to_vec(),
                    second: Some(BY_CRED_SECOND.to_vec()),
                },
            );
            vec![Ctap2PublicKeyCredentialDescriptor {
                r#type: Ctap2PublicKeyCredentialType::PublicKey,
                id: ByteBuf::from(
                    base64_url::decode(encoded)
                        .map_err(|e| format!("invalid credential id: {e}"))?,
                ),
                transports: None,
            }]
        }
        None => vec![],
    };

    let request = GetAssertionRequest {
        relying_party_id: RP_ID.to_owned(),
        challenge: vec![0x22; 32],
        origin: ORIGIN.to_owned(),
        top_origin: None,
        allow,
        user_verification: UserVerificationRequirement::Preferred,
        extensions: Some(GetAssertionRequestExtensions {
            prf: Some(PrfInput {
                eval: Some(PrfInputValue {
                    first: GET_EVAL_FIRST.to_vec(),
                    second: Some(GET_EVAL_SECOND.to_vec()),
                }),
                eval_by_credential,
            }),
            ..Default::default()
        }),
        timeout: TIMEOUT,
    };

    let response = retry_user_errors!(channel.webauthn_get_assertion(&request)).unwrap();

    for (num, assertion) in response.assertions.iter().enumerate() {
        let assertion_json = assertion
            .to_json_string(&request, JsonFormat::Prettified)
            .expect("Failed to serialize GetAssertion response");
        println!("Assertion {num} (JSON):\n{assertion_json}");
    }
    Ok(())
}
