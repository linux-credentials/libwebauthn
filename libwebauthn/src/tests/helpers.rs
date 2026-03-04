use std::time::Duration;

use rand::{thread_rng, Rng};
use tokio::sync::broadcast::Receiver;

use crate::ops::webauthn::{
    GetAssertionRequest, GetAssertionResponse, MakeCredentialRequest, MakeCredentialResponse,
    RelyingPartyId, WebAuthnIDL as _,
};
use crate::proto::ctap2::{Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialType};
use crate::transport::hid::channel::HidChannel;
use crate::webauthn::{Error, WebAuthn};
use crate::UvUpdate;

pub const TIMEOUT: Duration = Duration::from_secs(10);
pub const PIN: &str = "1234";

const RPID: &str = "example.org";

pub enum ExpectedUpdate {
    PresenceRequired,
    PinRequired,
}

/// Consumes UX updates from the channel and asserts they match the expected sequence.
/// PIN updates are automatically answered with [`PIN`].
/// Returns the receiver so callers can verify the queue is empty afterwards.
pub async fn handle_updates(
    mut rx: Receiver<UvUpdate>,
    expected: Vec<ExpectedUpdate>,
) -> Receiver<UvUpdate> {
    for exp in expected {
        let update = rx.recv().await.expect("Missing expected UvUpdate");
        match exp {
            ExpectedUpdate::PresenceRequired => {
                assert_eq!(update, UvUpdate::PresenceRequired);
            }
            ExpectedUpdate::PinRequired => {
                if let UvUpdate::PinRequired(p) = update {
                    p.send_pin(PIN).expect("Failed to send PIN");
                } else {
                    panic!("Expected PinRequired, got {:?}", update);
                }
            }
        }
    }
    rx
}

fn random_challenge_b64() -> String {
    let challenge: [u8; 32] = thread_rng().gen();
    base64_url::encode(&challenge)
}

fn user_id_b64(user_id: &[u8]) -> String {
    base64_url::encode(user_id)
}

/// MakeCredential for "example.org" via the JSON IDL interface.
pub async fn make_credential(
    channel: &mut HidChannel<'_>,
    user_id: &[u8],
    rk: &str,
    uv: &str,
    extensions_json: Option<&str>,
) -> Result<MakeCredentialResponse, Error> {
    let challenge = random_challenge_b64();
    let user_id_encoded = user_id_b64(user_id);
    let extensions_block = extensions_json
        .map(|e| format!(r#","extensions": {e}"#))
        .unwrap_or_default();

    let json = format!(
        r#"{{
            "rp": {{ "id": "{RPID}", "name": "Example" }},
            "user": {{ "id": "{user_id_encoded}", "name": "user", "displayName": "User" }},
            "challenge": "{challenge}",
            "pubKeyCredParams": [{{ "type": "public-key", "alg": -7 }}],
            "timeout": 10000,
            "excludeCredentials": [],
            "authenticatorSelection": {{
                "residentKey": "{rk}",
                "userVerification": "{uv}"
            }}{extensions_block}
        }}"#
    );

    let rpid = RelyingPartyId(RPID.to_owned());
    let request =
        MakeCredentialRequest::from_json(&rpid, &json).expect("Failed to parse MC request JSON");
    channel.webauthn_make_credential(&request).await
}

/// GetAssertion for "example.org" via the JSON IDL interface.
pub async fn get_assertion(
    channel: &mut HidChannel<'_>,
    allow: Vec<Ctap2PublicKeyCredentialDescriptor>,
    uv: &str,
    extensions_json: Option<&str>,
) -> Result<GetAssertionResponse, Error> {
    let challenge = random_challenge_b64();

    let allow_json: Vec<String> = allow
        .iter()
        .filter_map(|cred| {
            if cred.r#type != Ctap2PublicKeyCredentialType::PublicKey {
                return None;
            }
            let id = base64_url::encode(&cred.id);
            Some(format!(r#"{{ "type": "public-key", "id": "{id}" }}"#))
        })
        .collect();
    let allow_str = allow_json.join(", ");

    let extensions_block = extensions_json
        .map(|e| format!(r#","extensions": {e}"#))
        .unwrap_or_default();

    let json = format!(
        r#"{{
            "challenge": "{challenge}",
            "timeout": 10000,
            "rpId": "{RPID}",
            "allowCredentials": [{allow_str}],
            "userVerification": "{uv}"{extensions_block}
        }}"#
    );

    let rpid = RelyingPartyId(RPID.to_owned());
    let request =
        GetAssertionRequest::from_json(&rpid, &json).expect("Failed to parse GA request JSON");
    channel.webauthn_get_assertion(&request).await
}

/// Extract the credential descriptor from a MakeCredentialResponse.
pub fn credential_from(response: &MakeCredentialResponse) -> Ctap2PublicKeyCredentialDescriptor {
    (&response.authenticator_data).try_into().unwrap()
}
