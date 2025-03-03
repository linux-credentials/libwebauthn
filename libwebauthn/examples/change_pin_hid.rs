use std::error::Error;
use std::time::Duration;

use tracing_subscriber::{self, EnvFilter};

use libwebauthn::pin::{PinManagement, UvProvider, StdinPromptPinProvider};
use libwebauthn::transport::hid::list_devices;
use libwebauthn::transport::Device;
use libwebauthn::webauthn::Error as WebAuthnError;
use std::io::{self, Write};
use text_io::read;

const TIMEOUT: Duration = Duration::from_secs(10);

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .without_time()
        .init();
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    setup_logging();

    let devices = list_devices().await.unwrap();
    println!("Devices found: {:?}", devices);
    let pin_provider: Box<dyn UvProvider> = Box::new(StdinPromptPinProvider::new());

    for mut device in devices {
        println!("Selected HID authenticator: {}", &device);
        device.wink(TIMEOUT).await?;

        let mut channel = device.channel().await?;

        print!("PIN: Please enter the _new_ PIN: ");
        io::stdout().flush().unwrap();
        let new_pin: String = read!("{}\n");

        if &new_pin == "" {
            println!("PIN: No PIN provided, cancelling operation.");
            return Ok(());
        }

        let response = loop {
            match channel
                .change_pin(&pin_provider, new_pin.clone(), TIMEOUT)
                .await
            {
                Ok(response) => break Ok(response),
                Err(WebAuthnError::Ctap(ctap_error)) => {
                    if ctap_error.is_retryable_user_error() {
                        println!("Oops, try again! Error: {}", ctap_error);
                        continue;
                    }
                    break Err(WebAuthnError::Ctap(ctap_error));
                }
                Err(err) => break Err(err),
            };
        }
        .unwrap();
        println!("WebAuthn MakeCredential response: {:?}", response);
    }

    Ok(())
}
