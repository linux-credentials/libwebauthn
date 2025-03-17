use std::error::Error;
use std::fmt::Display;
use std::time::Duration;

use libwebauthn::management::AuthenticatorConfig;
use libwebauthn::pin::PinRequestReason;
use libwebauthn::proto::ctap2::{Ctap2, Ctap2GetInfoResponse};
use libwebauthn::transport::hid::list_devices;
use libwebauthn::transport::Device;
use libwebauthn::webauthn::Error as WebAuthnError;
use libwebauthn::UxUpdate;
use std::io::{self, Write};
use text_io::read;
use tokio::sync::mpsc::Receiver;
use tracing_subscriber::{self, EnvFilter};

const TIMEOUT: Duration = Duration::from_secs(10);

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .without_time()
        .init();
}

async fn handle_updates(mut state_recv: Receiver<UxUpdate>) {
    while let Some(update) = state_recv.recv().await {
        match update {
            UxUpdate::PresenceRequired => println!("Please touch your device!"),
            UxUpdate::UvRetry { attempts_left } => {
                print!("UV failed.");
                if let Some(attempts_left) = attempts_left {
                    print!(" You have {attempts_left} attempts left.");
                }
            }
            UxUpdate::PinRequired(update) => {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    ToggleAlwaysUv,
    EnableForceChangePin,
    DisableForceChangePin,
    SetMinPinLength(Option<u32>),
    SetMinPinLengthRpids,
    EnableEnterpriseAttestation,
}

impl Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::ToggleAlwaysUv => f.write_str("Toggle AlwaysUV"),
            Operation::EnableForceChangePin => f.write_str("Enable force change pin"),
            Operation::DisableForceChangePin => f.write_str("Disable force change pin"),
            Operation::SetMinPinLength(l) => {
                if let Some(length) = l {
                    f.write_fmt(format_args!("Set min PIN length. Current length: {length}"))
                } else {
                    f.write_str("Set min PIN length.")
                }
            }
            Operation::SetMinPinLengthRpids => f.write_str("Set min PIN length RPIDs"),
            Operation::EnableEnterpriseAttestation => f.write_str("Enable enterprise attestation"),
        }
    }
}

fn get_supported_options(info: &Ctap2GetInfoResponse) -> Vec<Operation> {
    let mut configure_ops = vec![];
    if let Some(options) = &info.options {
        if options.get("authnrCfg") == Some(&true) && options.get("alwaysUv").is_some() {
            configure_ops.push(Operation::ToggleAlwaysUv);
        }
        if options.get("authnrCfg") == Some(&true) && options.get("setMinPINLength").is_some() {
            if info.force_pin_change == Some(true) {
                configure_ops.push(Operation::DisableForceChangePin);
            } else {
                configure_ops.push(Operation::EnableForceChangePin);
            }
            configure_ops.push(Operation::SetMinPinLength(info.min_pin_length));
            configure_ops.push(Operation::SetMinPinLengthRpids);
        }
        if options.get("ep").is_some() {
            configure_ops.push(Operation::EnableEnterpriseAttestation);
        }
    }
    configure_ops
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

        tokio::spawn(handle_updates(state_recv));

        let info = channel.ctap2_get_info().await?;
        let options = get_supported_options(&info);

        println!("What do you want to do?");
        println!();
        for (idx, op) in options.iter().enumerate() {
            println!("({idx}) {op}");
        }

        let idx = loop {
            print!("Your choice: ");
            io::stdout().flush().expect("Failed to flush stdout!");
            let input: String = read!("{}\n");
            if let Ok(idx) = input.trim().parse::<usize>() {
                if idx < options.len() {
                    println!();
                    break idx;
                }
            }
        };

        let mut min_pin_length_rpids = Vec::new();
        if options[idx] == Operation::SetMinPinLengthRpids {
            loop {
                print!("Add RPIDs to list (enter empty string once finished): ");
                io::stdout().flush().expect("Failed to flush stdout!");
                let input: String = read!("{}\n");
                let trimmed = input.trim().to_string();
                if trimmed.is_empty() {
                    break;
                } else {
                    min_pin_length_rpids.push(trimmed);
                }
            }
        };

        let new_pin_length = if matches!(options[idx], Operation::SetMinPinLength(..)) {
            loop {
                print!("New minimum PIN length: ");
                io::stdout().flush().expect("Failed to flush stdout!");
                let input: String = read!("{}\n");
                match input.trim().parse::<u64>() {
                    Ok(l) => {
                        break l;
                    }
                    Err(_) => continue,
                }
            }
        } else {
            0
        };

        loop {
            let action = match options[idx] {
                Operation::ToggleAlwaysUv => channel.toggle_always_uv(TIMEOUT),
                Operation::SetMinPinLengthRpids => {
                    channel.set_min_pin_length_rpids(min_pin_length_rpids.clone(), TIMEOUT)
                }
                Operation::SetMinPinLength(..) => {
                    channel.set_min_pin_length(new_pin_length, TIMEOUT)
                }
                Operation::EnableEnterpriseAttestation => {
                    channel.enable_enterprise_attestation(TIMEOUT)
                }
                Operation::EnableForceChangePin => channel.force_change_pin(true, TIMEOUT),
                Operation::DisableForceChangePin => channel.force_change_pin(false, TIMEOUT),
            };
            match action.await {
                Ok(_) => break Ok(()),
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
        println!("Authenticator config done!");
    }

    Ok(())
}
