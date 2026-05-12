use std::error::Error;
use std::time::Duration;

use libwebauthn::ops::u2f::{RegisterRequest, SignRequest};
use libwebauthn::transport::ble::list_devices;
use libwebauthn::transport::{Channel as _, Device};
use libwebauthn::u2f::U2F;

#[path = "../common/mod.rs"]
mod common;

const TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    common::setup_logging();

    let devices = list_devices().await?;
    println!("Found {} devices.", devices.len());

    for mut device in devices {
        let mut channel = device.channel().await?;

        const APP_ID: &str = "https://foo.example.org";
        let challenge: &[u8] =
            &base64_url::decode("1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70").unwrap();

        // Registration ceremony
        println!("Registration request sent (timeout: {:?}).", TIMEOUT);
        let register_request =
            RegisterRequest::new_u2f_v2(APP_ID, challenge, vec![], TIMEOUT, false);

        let state_recv = channel.get_ux_update_receiver();
        tokio::spawn(common::handle_uv_updates(state_recv));

        let response = channel.u2f_register(&register_request).await?;
        println!("Response: {:?}", response);

        // Signature ceremony
        println!("Signature request sent (timeout: {:?}).", TIMEOUT);
        let new_key = response.as_registered_key()?;
        let sign_request = SignRequest::new(APP_ID, challenge, &new_key.key_handle, TIMEOUT, true);
        let response = channel.u2f_sign(&sign_request).await?;
        println!("Response: {:?}", response);
    }

    Ok(())
}
