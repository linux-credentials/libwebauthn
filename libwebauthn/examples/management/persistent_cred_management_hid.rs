//! Read-only credential management backed by a persistent pinUvAuthToken (pcmr).
//!
//! A persistent token (CTAP 2.2+) lets a credential manager enumerate passkeys without
//! re-prompting for the PIN on every launch or replug: the platform mints the token once
//! and reuses it on later connections, until a PIN change or authenticator reset.
//!
//! The token is a long-lived bearer secret, so store it with confidentiality equivalent
//! to other credential secrets (an OS keyring, or encrypted-at-rest with OS access
//! control). This example uses the in-memory [`MemoryPersistentTokenStore`], which keeps
//! records for the lifetime of the process and so demonstrates same-session reuse.

use std::sync::Arc;
use std::time::Duration;

use libwebauthn::management::CredentialManagement;
use libwebauthn::pin::persistent_token::{MemoryPersistentTokenStore, PersistentTokenStore};
use libwebauthn::proto::ctap2::Ctap2;
use libwebauthn::transport::hid::list_devices;
use libwebauthn::transport::hid::HidError;
use libwebauthn::transport::{Channel as _, ChannelSettings, Device};
use libwebauthn::webauthn::WebAuthnError;

#[path = "../common/mod.rs"]
mod common;

const TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
pub async fn main() -> Result<(), WebAuthnError<HidError>> {
    common::setup_logging();

    // In production, use a securely stored implementation. See the module docs.
    let store: Arc<dyn PersistentTokenStore> = Arc::new(MemoryPersistentTokenStore::new());

    let devices = list_devices().await.unwrap();
    println!("Devices found: {:?}", devices);

    for mut device in devices {
        println!("Selected HID authenticator: {}", device);

        // Pass the store via ChannelSettings; the channel reuses or mints a persistent
        // token through it. The same settings apply to any transport.
        let settings = ChannelSettings {
            persistent_token_store: Some(store.clone()),
        };
        let mut channel = device.channel(settings).await?;
        let state_recv = channel.get_ux_update_receiver();
        tokio::spawn(common::handle_uv_updates(state_recv));

        let info = channel.ctap2_get_info().await?;
        if !info.supports_credential_management() {
            println!("This authenticator does not support credential management.");
            continue;
        }
        if !info.supports_persistent_credential_management_read_only() {
            println!(
                "This authenticator does not advertise perCredMgmtRO. Read-only credential \
                 management will use an ordinary (ephemeral) pinUvAuthToken and prompt for \
                 the PIN as usual."
            );
        }

        // First pass: with an empty store the platform mints a persistent token, so a PIN
        // prompt is expected (a UV-capable authenticator may prompt for a touch instead).
        println!("\nFirst enumeration (expect a PIN prompt if nothing is cached yet):");
        print_metadata(&mut channel).await?;

        // Second pass: the persistent token is recognized in the store and reused, so no
        // PIN prompt. With a durable store this also holds across restarts and replugs.
        println!("\nSecond enumeration (persistent token reused, no PIN prompt expected):");
        print_metadata(&mut channel).await?;

        return Ok(());
    }

    Ok(())
}

async fn print_metadata<T: CredentialManagement>(
    channel: &mut T,
) -> Result<(), WebAuthnError<T::TransportError>> {
    let metadata = channel.get_credential_metadata(TIMEOUT).await?;
    println!(
        "Discoverable credentials: {} (max remaining: {})",
        metadata.existing_resident_credentials_count,
        metadata.max_possible_remaining_resident_credentials_count,
    );
    Ok(())
}
