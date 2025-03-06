use libwebauthn::StateUpdate;
use std::error::Error;
use std::fmt::Display;
use std::io::{self, Write};
use std::time::Duration;
use text_io::read;
use tokio::sync::mpsc::Receiver;
use tracing_subscriber::{self, EnvFilter};

use libwebauthn::management::BioEnrollment;
use libwebauthn::pin::PinRequestReason;
use libwebauthn::proto::ctap2::{Ctap2, Ctap2GetInfoResponse, Ctap2LastEnrollmentSampleStatus};
use libwebauthn::transport::hid::list_devices;
use libwebauthn::transport::Device;
use libwebauthn::webauthn::Error as WebAuthnError;

const TIMEOUT: Duration = Duration::from_secs(10);

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .without_time()
        .init();
}

async fn handle_updates(mut state_recv: Receiver<StateUpdate>) {
    while let Some(update) = state_recv.recv().await {
        match update {
            StateUpdate::PresenceRequired => println!("Please touch your device!"),
            StateUpdate::UvRetry { attempts_left } => {
                print!("UV failed.");
                if let Some(attempts_left) = attempts_left {
                    print!(" You have {attempts_left} attempts left.");
                }
            }
            StateUpdate::PinRequired {
                reply_to,
                reason,
                attempts_left,
            } => {
                let mut attempts_str = String::new();
                if let Some(attempts) = attempts_left {
                    attempts_str = format!(". You have {attempts} attempts left!");
                };

                match reason {
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
                } else {
                    let _ = reply_to.send(pin_raw);
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    GetModality,
    GetFingerprintSensorInfo,
    EnumerateEnrollments,
    RemoveEnrollment,
    RenameEnrollment,
    AddNewEnrollment,
}

impl Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::GetModality => f.write_str("Get modality"),
            Operation::GetFingerprintSensorInfo => f.write_str("Get fingerprint sensor info"),
            Operation::EnumerateEnrollments => f.write_str("Enumerate enrollments"),
            Operation::RemoveEnrollment => f.write_str("Remove enrollment"),
            Operation::RenameEnrollment => f.write_str("Rename enrollment"),
            Operation::AddNewEnrollment => f.write_str("Start new enrollment"),
        }
    }
}

fn get_supported_options(info: &Ctap2GetInfoResponse) -> Vec<Operation> {
    let mut configure_ops = vec![];
    if info.supports_bio_enrollment() {
        configure_ops.push(Operation::GetModality);
        configure_ops.push(Operation::GetFingerprintSensorInfo);
        if info.has_bio_enrollments() {
            configure_ops.push(Operation::EnumerateEnrollments);
            configure_ops.push(Operation::RemoveEnrollment);
            configure_ops.push(Operation::RenameEnrollment);
        }
        configure_ops.push(Operation::AddNewEnrollment);
    }
    configure_ops
}

fn ask_for_user_input(num_of_items: usize) -> usize {
    let idx = loop {
        print!("Your choice: ");
        io::stdout().flush().expect("Failed to flush stdout!");
        let input: String = read!("{}\n");
        if let Ok(idx) = input.trim().parse::<usize>() {
            if idx < num_of_items {
                println!();
                break idx;
            }
        }
    };
    idx
}

fn print_status_update(enrollment_status: Ctap2LastEnrollmentSampleStatus, remaining_samples: u64) {
    use Ctap2LastEnrollmentSampleStatus as S;
    print!("Last sample status: ");
    match enrollment_status {
        S::Ctap2EnrollFeedbackFpGood => print!("Good"),
        S::Ctap2EnrollFeedbackFpTooHigh => print!("Fingerprint too high"),
        S::Ctap2EnrollFeedbackFpTooLow => print!("Fingerprint too low"),
        S::Ctap2EnrollFeedbackFpTooLeft => print!("Fingerprint too left"),
        S::Ctap2EnrollFeedbackFpTooRight => print!("Fingerprint too right"),
        S::Ctap2EnrollFeedbackFpTooFast => print!("Fingerprint too fast"),
        S::Ctap2EnrollFeedbackFpTooSlow => print!("Fingerprint too slow"),
        S::Ctap2EnrollFeedbackFpPoorQuality => print!("Fingerprint poor quality"),
        S::Ctap2EnrollFeedbackFpTooSkewed => print!("Fingerprint too skewed"),
        S::Ctap2EnrollFeedbackFpTooShort => print!("Fingerprint too short"),
        S::Ctap2EnrollFeedbackFpMergeFailure => print!("Fingerprint merge failure"),
        S::Ctap2EnrollFeedbackFpExists => print!("Fingerprint exists"),
        S::Unused => print!("<Unused>"),
        S::Ctap2EnrollFeedbackNoUserActivity => print!("No user activity"),
        S::Ctap2EnrollFeedbackNoUserPresenceTransition => print!("No user presence transition"),
    }
    println!(", Remaining samples needed: {remaining_samples}");
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

        let idx = ask_for_user_input(options.len());
        let resp = 'outer: loop {
            let action = match options[idx] {
                Operation::GetModality => channel
                    .get_bio_modality(TIMEOUT)
                    .await
                    .map(|x| format!("{x:?}")),
                Operation::GetFingerprintSensorInfo => channel
                    .get_fingerprint_sensor_info(TIMEOUT)
                    .await
                    .map(|x| format!("{x:?}")),
                Operation::EnumerateEnrollments => channel
                    .get_bio_enrollments(TIMEOUT)
                    .await
                    .map(|x| format!("{x:?}")),
                Operation::RemoveEnrollment => {
                    let enrollments = loop {
                        match channel.get_bio_enrollments(TIMEOUT).await {
                            Ok(r) => break r,
                            Err(WebAuthnError::Ctap(ctap_error)) => {
                                if ctap_error.is_retryable_user_error() {
                                    println!("Oops, try again! Error: {}", ctap_error);
                                    continue;
                                }
                                break 'outer Err(WebAuthnError::Ctap(ctap_error));
                            }
                            Err(err) => break 'outer Err(err),
                        }
                    };
                    println!("Which enrollment do you want to remove?");
                    for (id, enrollment) in enrollments.iter().enumerate() {
                        println!("({id}) {enrollment:?}")
                    }
                    let idx = ask_for_user_input(enrollments.len());
                    channel
                        .remove_bio_enrollment(
                            &enrollments[idx].template_id.as_ref().unwrap(),
                            TIMEOUT,
                        )
                        .await
                        .map(|x| format!("{x:?}"))
                }
                Operation::RenameEnrollment => {
                    let enrollments = loop {
                        match channel.get_bio_enrollments(TIMEOUT).await {
                            Ok(r) => break r,
                            Err(WebAuthnError::Ctap(ctap_error)) => {
                                if ctap_error.is_retryable_user_error() {
                                    println!("Oops, try again! Error: {}", ctap_error);
                                    continue;
                                }
                                break 'outer Err(WebAuthnError::Ctap(ctap_error));
                            }
                            Err(err) => break 'outer Err(err),
                        }
                    };
                    println!("Which enrollment do you want to rename?");
                    for (id, enrollment) in enrollments.iter().enumerate() {
                        println!("({id}) {enrollment:?}")
                    }
                    let idx = ask_for_user_input(enrollments.len());
                    print!("New name: ");
                    io::stdout().flush().expect("Failed to flush stdout!");
                    let new_name: String = read!("{}\n");
                    channel
                        .rename_bio_enrollment(
                            &enrollments[idx].template_id.as_ref().unwrap(),
                            &new_name,
                            TIMEOUT,
                        )
                        .await
                        .map(|x| format!("{x:?}"))
                }
                Operation::AddNewEnrollment => {
                    let (template_id, mut sample_status, mut remaining_samples) =
                        match channel.start_new_bio_enrollment(None, TIMEOUT).await {
                            Ok(r) => r,
                            Err(WebAuthnError::Ctap(ctap_error)) => {
                                if ctap_error.is_retryable_user_error() {
                                    println!("Oops, try again! Error: {}", ctap_error);
                                    continue;
                                }
                                break Err(WebAuthnError::Ctap(ctap_error));
                            }
                            Err(err) => break Err(err),
                        };
                    while remaining_samples > 0 {
                        print_status_update(sample_status, remaining_samples);
                        (sample_status, remaining_samples) = match channel
                            .capture_next_bio_enrollment_sample(&template_id, None, TIMEOUT)
                            .await
                        {
                            Ok(r) => r,
                            Err(WebAuthnError::Ctap(ctap_error)) => {
                                if ctap_error.is_retryable_user_error() {
                                    println!("Oops, try again! Error: {}", ctap_error);
                                    continue;
                                }
                                break 'outer Err(WebAuthnError::Ctap(ctap_error));
                            }
                            Err(err) => break 'outer Err(err),
                        };
                    }
                    Ok(format!("Success!"))
                }
            };
            match action {
                Ok(r) => break Ok(r),
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
        println!("Bio enrollment command done: {resp}");
    }

    Ok(())
}
