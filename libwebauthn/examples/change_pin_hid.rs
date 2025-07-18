use std::error::Error;
use std::time::Duration;

use libwebauthn::{
    pin::{PinManagement, PinRequestReason},
    UvUpdate,
};
use tokio::sync::mpsc::Receiver;
use tracing_subscriber::{self, EnvFilter};

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

async fn handle_updates(mut state_recv: Receiver<UvUpdate>) {
    while let Some(update) = state_recv.recv().await {
        match update {
            UvUpdate::PresenceRequired => println!("Please touch your device!"),
            UvUpdate::UvRetry { attempts_left } => {
                print!("UV failed.");
                if let Some(attempts_left) = attempts_left {
                    print!(" You have {attempts_left} attempts left.");
                }
            }
            UvUpdate::PinRequired(update) => {
                let mut attempts_str = String::new();
                if let Some(attempts) = update.attempts_left {
                    attempts_str = format!(". You have {attempts} attempts left!");
                };

                match update.reason {
                    PinRequestReason::RelyingPartyRequest => println!("RP required a PIN."),
                    PinRequestReason::AuthenticatorPolicy => {
                        println!("Your device requires a PIN.")
                    }
                    PinRequestReason::FallbackFromUV => {
                        println!("UV failed too often and is blocked. Falling back to PIN.")
                    }
                }
                print!("PIN: Please enter the PIN for your authenticator{attempts_str}: ");
                io::stdout().flush().unwrap();
                let pin_raw: String = read!("{}\n");

                if pin_raw.is_empty() {
                    println!("PIN: No PIN provided, cancelling operation.");
                    update.cancel();
                } else {
                    let _ = update.send_pin(&pin_raw);
                }
            }
        }
    }
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    setup_logging();

    let devices = list_devices().await.unwrap();
    println!("Devices found: {:?}", devices);

    for mut device in devices {
        println!("Selected HID authenticator: {}", &device);
        let (mut channel, state_recv) = device.channel().await?;
        channel.wink(TIMEOUT).await?;

        print!("PIN: Please enter the _new_ PIN: ");
        io::stdout().flush().unwrap();
        let new_pin: String = read!("{}\n");

        if &new_pin == "" {
            println!("PIN: No PIN provided, cancelling operation.");
            return Ok(());
        }

        tokio::spawn(handle_updates(state_recv));

        let response = loop {
            match channel.change_pin(new_pin.clone(), TIMEOUT).await {
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
        println!("WebAuthn response: {:?}", response);
    }

    Ok(())
}
