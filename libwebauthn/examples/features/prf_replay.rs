use std::collections::HashMap;
use std::convert::TryInto;
use std::error::Error;
use std::time::Duration;

use libwebauthn::transport::hid::channel::HidChannel;
use rand::{thread_rng, Rng};
use serde_bytes::ByteBuf;

use libwebauthn::ops::webauthn::{
    GetAssertionRequest, GetAssertionRequestExtensions, PRFValue, PrfInput,
    UserVerificationRequirement,
};
use libwebauthn::proto::ctap2::{Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialType};
use libwebauthn::transport::hid::list_devices;
use libwebauthn::transport::{Channel as _, Device};
use libwebauthn::webauthn::WebAuthn;

#[path = "../common/mod.rs"]
mod common;

const TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    common::setup_logging();

    let argv: Vec<_> = std::env::args().collect();
    if argv.len() != 3 {
        println!("Usage: cargo run --example prf_replay -- CREDENTIAL_ID FIRST_PRF_INPUT");
        println!();
        println!("CREDENTIAL_ID:   Credential ID to be used to sign against, as a hexstring (like 5830c80ae90f7865c631626573f1fdc7..)");
        println!(
            "FIRST_PRF_INPUT: PRF input to be used as a hexstring. Needs to be 32 bytes long!"
        );
        println!();
        println!("How to use:");
        println!("1. Go to https://demo.yubico.com/webauthn-developers");
        println!("2. Register there with PRF extension enabled, using your favorite browser");
        println!("3. Sign in, with FIRST_PRF_INPUT set");
        println!("4. Copy out the used hexstrings for credential_id and PRF input, and use them with this example");
        println!("5. Hope the outputs match");
        return Ok(());
    }
    let credential_id =
        hex::decode(argv[1].clone()).expect("CREDENTIAL_ID is not a valid hex code");
    let first_prf_input = hex::decode(argv[2].clone())
        .expect("FIRST_PRF_INPUT is not a valid hex code")
        .try_into()
        .expect("FIRST_PRF_INPUT is not exactly 32 bytes long");

    let devices = list_devices().await.unwrap();
    println!("Devices found: {:?}", devices);

    let challenge: [u8; 32] = thread_rng().gen();

    for mut device in devices {
        println!("Selected HID authenticator: {}", &device);
        let mut channel = device.channel().await?;
        channel.wink(TIMEOUT).await?;

        let state_recv = channel.get_ux_update_receiver();
        tokio::spawn(common::handle_uv_updates(state_recv));

        let credential = Ctap2PublicKeyCredentialDescriptor {
            r#type: Ctap2PublicKeyCredentialType::PublicKey,
            id: ByteBuf::from(credential_id.as_slice()),
            transports: None,
        };

        let prf = PrfInput {
            eval: Some(PRFValue {
                first: first_prf_input,
                second: None,
            }),
            eval_by_credential: HashMap::new(),
        };

        run_success_test(&mut channel, &credential, &challenge, prf, "PRF output: ").await;
    }
    Ok(())
}

async fn run_success_test(
    channel: &mut HidChannel<'_>,
    credential: &Ctap2PublicKeyCredentialDescriptor,
    challenge: &[u8; 32],
    prf: PrfInput,
    printoutput: &str,
) {
    let get_assertion = GetAssertionRequest {
        relying_party_id: "demo.yubico.com".to_owned(),
        challenge: Vec::from(challenge),
        origin: "demo.yubico.com".to_string(),
        top_origin: None,
        allow: vec![credential.clone()],
        user_verification: UserVerificationRequirement::Preferred,
        extensions: Some(GetAssertionRequestExtensions {
            prf: Some(prf),
            ..Default::default()
        }),
        timeout: TIMEOUT,
    };

    let response = retry_user_errors!(channel.webauthn_get_assertion(&get_assertion)).unwrap();
    for (num, assertion) in response.assertions.iter().enumerate() {
        println!(
            "{num}. result of {printoutput}: {:?}",
            assertion
                .unsigned_extensions_output
                .as_ref()
                .map(|e| if let Some(prf) = &e.prf {
                    let results = prf.results.as_ref().map(|r| hex::encode(r.first)).unwrap();
                    format!("Found PRF results: {}", results)
                } else if e.hmac_get_secret.is_some() {
                    String::from("ERROR: Got HMAC instead of PRF output")
                } else {
                    String::from("ERROR: No PRF output")
                })
                .unwrap_or(String::from("ERROR: No extensions returned"))
        );
    }
}
