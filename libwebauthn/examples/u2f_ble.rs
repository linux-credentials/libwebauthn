use std::error::Error;
use std::time::Duration;

use libwebauthn::UvUpdate;
use tokio::sync::mpsc::Receiver;
use tracing_subscriber::{self, EnvFilter};

use libwebauthn::ops::u2f::{RegisterRequest, SignRequest};
use libwebauthn::transport::ble::list_devices;
use libwebauthn::transport::Device;
use libwebauthn::u2f::U2F;

const TIMEOUT: Duration = Duration::from_secs(10);

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .without_time()
        .init();
}

async fn handle_updates(mut state_recv: Receiver<UvUpdate>) {
    while let Some(update) = state_recv.recv().await {
        match update {
            UvUpdate::PresenceRequired => println!("Please touch your device!"),
            _ => { /* U2F doesn't use other state updates */ }
        }
    }
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    setup_logging();

    let devices = list_devices().await?;
    println!("Found {} devices.", devices.len());

    for mut device in devices {
        let (mut channel, state_recv) = device.channel().await?;

        const APP_ID: &str = "https://foo.example.org";
        let challenge: &[u8] =
            &base64_url::decode("1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70").unwrap();
        // Registration ceremony
        println!("Registration request sent (timeout: {:?}).", TIMEOUT);
        let register_request =
            RegisterRequest::new_u2f_v2(&APP_ID, &challenge, vec![], TIMEOUT, false);

        tokio::spawn(handle_updates(state_recv));
        let response = channel.u2f_register(&register_request).await?;
        println!("Response: {:?}", response);

        // Signature ceremony
        println!("Signature request sent (timeout: {:?} seconds).", TIMEOUT);
        let new_key = response.as_registered_key()?;
        let sign_request =
            SignRequest::new(&APP_ID, &challenge, &new_key.key_handle, TIMEOUT, true);
        let response = channel.u2f_sign(&sign_request).await?;
        println!("Response: {:?}", response);
    }

    Ok(())
}
