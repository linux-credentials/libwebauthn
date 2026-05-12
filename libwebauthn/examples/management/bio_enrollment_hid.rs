use std::error::Error;
use std::fmt::Display;
use std::io::{self, Write};
use std::time::Duration;
use text_io::read;

use libwebauthn::management::BioEnrollment;
use libwebauthn::proto::ctap2::{Ctap2, Ctap2GetInfoResponse, Ctap2LastEnrollmentSampleStatus};
use libwebauthn::transport::hid::list_devices;
use libwebauthn::transport::{Channel as _, Device};
use libwebauthn::webauthn::Error as WebAuthnError;

#[path = "../common/mod.rs"]
mod common;

const TIMEOUT: Duration = Duration::from_secs(10);

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
    common::setup_logging();

    let devices = list_devices().await.unwrap();
    println!("Devices found: {:?}", devices);

    for mut device in devices {
        println!("Selected HID authenticator: {}", device);
        let mut channel = device.channel().await?;
        channel.wink(TIMEOUT).await?;

        let state_recv = channel.get_ux_update_receiver();
        tokio::spawn(common::handle_uv_updates(state_recv));

        let info = channel.ctap2_get_info().await?;
        let options = get_supported_options(&info);

        println!("What do you want to do?");
        println!();
        for (idx, op) in options.iter().enumerate() {
            println!("({idx}) {op}");
        }

        let idx = common::prompt_index(options.len());
        let result: Result<String, WebAuthnError> = match options[idx] {
            Operation::GetModality => {
                retry_user_errors!(channel.get_bio_modality(TIMEOUT)).map(|x| format!("{x:?}"))
            }
            Operation::GetFingerprintSensorInfo => {
                retry_user_errors!(channel.get_fingerprint_sensor_info(TIMEOUT))
                    .map(|x| format!("{x:?}"))
            }
            Operation::EnumerateEnrollments => {
                retry_user_errors!(channel.get_bio_enrollments(TIMEOUT)).map(|x| format!("{x:?}"))
            }
            Operation::RemoveEnrollment => {
                let enrollments = retry_user_errors!(channel.get_bio_enrollments(TIMEOUT))?;
                println!("Which enrollment do you want to remove?");
                for (id, enrollment) in enrollments.iter().enumerate() {
                    println!("({id}) {enrollment:?}")
                }
                let idx = common::prompt_index(enrollments.len());
                retry_user_errors!(channel
                    .remove_bio_enrollment(enrollments[idx].template_id.as_ref().unwrap(), TIMEOUT))
                .map(|x| format!("{x:?}"))
            }
            Operation::RenameEnrollment => {
                let enrollments = retry_user_errors!(channel.get_bio_enrollments(TIMEOUT))?;
                println!("Which enrollment do you want to rename?");
                for (id, enrollment) in enrollments.iter().enumerate() {
                    println!("({id}) {enrollment:?}")
                }
                let idx = common::prompt_index(enrollments.len());
                print!("New name: ");
                io::stdout().flush().expect("Failed to flush stdout!");
                let new_name: String = read!("{}\n");
                retry_user_errors!(channel.rename_bio_enrollment(
                    enrollments[idx].template_id.as_ref().unwrap(),
                    &new_name,
                    TIMEOUT
                ))
                .map(|x| format!("{x:?}"))
            }
            Operation::AddNewEnrollment => {
                let (template_id, mut sample_status, mut remaining_samples) =
                    retry_user_errors!(channel.start_new_bio_enrollment(None, TIMEOUT))?;
                while remaining_samples > 0 {
                    print_status_update(sample_status, remaining_samples);
                    (sample_status, remaining_samples) = retry_user_errors!(
                        channel.capture_next_bio_enrollment_sample(&template_id, None, TIMEOUT)
                    )?;
                }
                Ok("Success!".to_string())
            }
        };
        let resp = result.unwrap();
        println!("Bio enrollment command done: {resp}");
    }

    Ok(())
}
