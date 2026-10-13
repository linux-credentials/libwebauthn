//! caBLE / CTAP 2.3 hybrid: the QR advertises both the WebSocket tunnel and
//! the BLE L2CAP channel so the authenticator can pick either one. Transient
//! MakeCredential only.
use std::error::Error;

use libwebauthn_varlink_client::WebauthnProxy;
use libwebauthn_varlink_types::{VarlinkOperation, VarlinkRequestOrigin, VarlinkTransportMode};
use zlink::tokio::unix;

#[path = "common/mod.rs"]
mod common;

// Where do we get a unique user ID
// Note, that rp.icon is deprecated and not supported by Android
const MAKE_CREDENTIAL_REQUEST: &str = r#"
{
    "rp": {
        "id": "gnome.computer",
        "name": "Gnome Desktop"
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

    let (_server, socket_path) = common::spawn_private_server().await?;
    let mut conn = unix::connect(&socket_path).await?;

    let available = match conn.is_available().await? {
        Ok(reply) => reply.available,
        Err(err) => return Err(format!("is_available failed: {err}").into()),
    };
    if !available {
        eprintln!("No Bluetooth adapter found. Cable/Hybrid transport is unavailable.");
        return Err("Cable transport not available".into());
    }

    let device_connection = match conn
        .future_device_connection(
            VarlinkOperation::MakeCredential,
            VarlinkTransportMode::CloudOrBle,
        )
        .await?
    {
        Ok(reply) => reply,
        Err(err) => return Err(format!("future_device_connection failed: {err}").into()),
    };

    println!("Created QR code, awaiting for advertisement.");
    common::print_qr_code(&device_connection.qr_contents);

    common::stream_ceremony(&socket_path, conn.await_connecting().await?).await?;
    println!("Channel established.");

    let request_origin: VarlinkRequestOrigin =
        "https://gnome.computer".try_into().expect("Invalid origin");
    let event = common::stream_ceremony(
        &socket_path,
        conn.webauthn_make_credential(request_origin, MAKE_CREDENTIAL_REQUEST.to_string())
            .await?,
    )
    .await?;
    if let Some(response_json) = event.response_json {
        println!("WebAuthn MakeCredential response (JSON):\n{response_json}");
    }

    if let Err(err) = conn.close_channel().await? {
        eprintln!("close_channel failed: {err}");
    }

    Ok(())
}
