use std::fmt::Display;
use std::time::Duration;

use libwebauthn::management::CredentialManagement;
use libwebauthn::proto::ctap2::{
    Ctap2, Ctap2CredentialData, Ctap2PublicKeyCredentialRpEntity, Ctap2RPData,
};
use libwebauthn::proto::CtapError;
use libwebauthn::transport::hid::list_devices;
use libwebauthn::transport::{Channel as _, Device};
use libwebauthn::webauthn::Error as WebAuthnError;
use std::io::{self, Write};
use text_io::read;

#[path = "../common/mod.rs"]
mod common;

const TIMEOUT: Duration = Duration::from_secs(10);

fn format_rp(rp: &Ctap2PublicKeyCredentialRpEntity) -> String {
    rp.name.clone().unwrap_or(rp.id.clone())
}

fn format_credential(cred: &Ctap2CredentialData) -> String {
    cred.user
        .display_name
        .clone()
        .unwrap_or(cred.user.name.clone().unwrap_or("<No username>".into()))
        .to_string()
}

async fn enumerate_rps<T: CredentialManagement>(
    channel: &mut T,
) -> Result<Vec<Ctap2RPData>, WebAuthnError> {
    let (rp, total_rps) = retry_user_errors!(channel.enumerate_rps_begin(TIMEOUT))?;
    let mut rps = vec![rp];
    for _ in 1..total_rps {
        let rp = retry_user_errors!(channel.enumerate_rps_next_rp(TIMEOUT))?;
        rps.push(rp);
    }
    Ok(rps)
}

async fn enumerate_credentials_for_rp<T: CredentialManagement>(
    channel: &mut T,
    rp_id_hash: &[u8],
) -> Result<Vec<Ctap2CredentialData>, WebAuthnError> {
    let (credential, num_of_creds) =
        retry_user_errors!(channel.enumerate_credentials_begin(rp_id_hash, TIMEOUT))?;
    let mut credentials = vec![credential];
    for _ in 1..num_of_creds {
        let credential = retry_user_errors!(channel.enumerate_credentials_next(TIMEOUT))?;
        credentials.push(credential);
    }
    Ok(credentials)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    GetMetadata,
    EnumerateRPs,
    EnumerateCredentials,
    RemoveCredential,
    UpdateUserInfo,
}

impl Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::GetMetadata => f.write_str("Get metadata"),
            Operation::EnumerateRPs => f.write_str("Enumerate relying parties"),
            Operation::EnumerateCredentials => f.write_str("Enumerate credentials"),
            Operation::RemoveCredential => f.write_str("Remove credential"),
            Operation::UpdateUserInfo => f.write_str("Update user info"),
        }
    }
}

#[tokio::main]
pub async fn main() -> Result<(), WebAuthnError> {
    common::setup_logging();

    let devices = list_devices().await.unwrap();
    println!("Devices found: {:?}", devices);

    for mut device in devices {
        println!("Selected HID authenticator: {}", &device);
        let mut channel = device.channel().await?;
        channel.wink(TIMEOUT).await?;

        let state_recv = channel.get_ux_update_receiver();
        tokio::spawn(common::handle_uv_updates(state_recv));

        let info = channel.ctap2_get_info().await?;

        if !info.supports_credential_management() {
            println!("Your token does not support credential management.");
            return Err(WebAuthnError::Ctap(CtapError::InvalidCommand));
        }

        let options = [
            Operation::GetMetadata,
            Operation::EnumerateRPs,
            Operation::EnumerateCredentials,
            Operation::RemoveCredential,
            Operation::UpdateUserInfo,
        ];

        println!("What do you want to do?");
        println!();
        for (idx, op) in options.iter().enumerate() {
            println!("({idx}) {op}");
        }

        let idx = common::prompt_index(options.len());
        let metadata = retry_user_errors!(channel.get_credential_metadata(TIMEOUT))?;
        if options[idx] == Operation::GetMetadata {
            println!("Metadata: {metadata:#?}");
            return Ok(());
        }

        let rps = enumerate_rps(&mut channel).await?;
        if options[idx] == Operation::EnumerateRPs {
            println!("RPs:");
            for rp in &rps {
                println!("{}", format_rp(&rp.rp));
            }
            return Ok(());
        }

        let mut credlist = Vec::new();
        for rp in &rps {
            let creds = enumerate_credentials_for_rp(&mut channel, &rp.rp_id_hash).await?;
            for cred in creds {
                credlist.push((rp.rp.clone(), cred));
            }
        }
        if options[idx] == Operation::EnumerateCredentials {
            println!("Credentials:");
            for (rp, cred) in &credlist {
                println!("{}: {}", format_rp(rp), format_credential(cred));
            }
            return Ok(());
        }

        for (idx, (rp, cred)) in credlist.iter().enumerate() {
            println!("({idx}) {}: {}", format_rp(rp), format_credential(cred));
        }

        let cred_idx = common::prompt_index(credlist.len());

        if options[idx] == Operation::RemoveCredential {
            let (_, cred) = &credlist[cred_idx];
            retry_user_errors!(channel.delete_credential(&cred.credential_id, TIMEOUT))?;
            println!("Done");
            return Ok(());
        }

        if options[idx] == Operation::UpdateUserInfo {
            let name = loop {
                print!("New user name: ");
                io::stdout().flush().expect("Failed to flush stdout!");
                let input: String = read!("{}\n");
                let input = input.trim();
                if !input.is_empty() {
                    println!();
                    break input.to_string();
                }
            };
            let (_rp, cred) = &credlist[cred_idx];
            let mut user = cred.user.clone();
            user.name = Some(name);
            retry_user_errors!(channel.update_user_info(&cred.credential_id, &user, TIMEOUT))?;
            println!("Done");
            return Ok(());
        }
    }

    Ok(())
}
