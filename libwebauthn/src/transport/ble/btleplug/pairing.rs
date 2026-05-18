//! Bonding enforcement for BLE FIDO authenticators.
//!
//! CTAP 2.2 §11.4 requires the platform-authenticator BLE link to be
//! bonded with LE Secure Connections. btleplug doesn't surface bonding
//! state, so on Linux we query bluez's `org.bluez.Device1.{Paired,Bonded}`
//! directly. Pairing itself is the OS's responsibility (e.g.
//! `bluetoothctl pair <ADDR>`); this module only verifies the link.

use btleplug::api::{BDAddr, Peripheral as _};
use btleplug::platform::Peripheral;
use tracing::{debug, info, warn};

use super::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BondingState {
    Bonded,
    NotBonded,
    /// Bonding state could not be determined (non-bluez backend or DBus
    /// unreachable); the caller decides whether to proceed.
    Unknown,
}

/// Reads `Paired` and `Bonded` from bluez DBus for `peripheral`.
pub(crate) async fn check_bonded(peripheral: &Peripheral) -> BondingState {
    let address = peripheral.address();
    debug!(?address, "Checking bonded state via bluez DBus");

    let result = tokio::task::spawn_blocking(move || query_bluez_bonded(address)).await;

    match result {
        Ok(Ok((paired, bonded))) => {
            info!(?address, paired, bonded, "bluez bonding state");
            if paired && bonded {
                BondingState::Bonded
            } else {
                BondingState::NotBonded
            }
        }
        Ok(Err(e)) => {
            warn!(?address, error = ?e, "Could not query bluez bonding state");
            BondingState::Unknown
        }
        Err(e) => {
            warn!(error = ?e, "bluez bonding query task panicked");
            BondingState::Unknown
        }
    }
}

/// Returns `Err(ConnectionFailed)` when the device is reachable but
/// explicitly not bonded; falls through on `Unknown`.
pub(crate) async fn enforce_bonded(peripheral: &Peripheral) -> Result<(), Error> {
    match check_bonded(peripheral).await {
        BondingState::Bonded => Ok(()),
        BondingState::Unknown => {
            warn!(
                "Could not verify LE Secure Connections bonding via bluez; \
                 proceeding under OS pairing enforcement"
            );
            Ok(())
        }
        BondingState::NotBonded => {
            warn!(
                "BLE FIDO authenticator is not bonded with LE Secure Connections; \
                 CTAP 2.2 §11.4 requires bonding. Pair the device via the OS \
                 (e.g. `bluetoothctl pair <ADDR>`) before retrying."
            );
            Err(Error::ConnectionFailed)
        }
    }
}

/// btleplug doesn't expose the adapter index, so we walk the bluez
/// ObjectManager tree and match the first device with this address.
fn query_bluez_bonded(address: BDAddr) -> Result<(bool, bool), String> {
    use dbus::arg::{PropMap, RefArg};
    use dbus::blocking::stdintf::org_freedesktop_dbus::ObjectManager;
    use dbus::blocking::{Connection, Proxy};
    use std::time::Duration as StdDuration;

    let conn = Connection::new_system().map_err(|e| format!("dbus connect: {e}"))?;
    let manager = Proxy::new("org.bluez", "/", StdDuration::from_secs(2), &conn);
    let objects = manager
        .get_managed_objects()
        .map_err(|e| format!("GetManagedObjects: {e}"))?;

    let mac_lower = format!("{:x}", address);
    let dev_segment = format!("dev_{}", mac_lower.replace(':', "_").to_uppercase());

    for (path, interfaces) in objects {
        let path_str = path.to_string();
        if !path_str.starts_with("/org/bluez/") || !path_str.ends_with(&dev_segment) {
            continue;
        }
        let Some(device_props): Option<&PropMap> = interfaces.get("org.bluez.Device1") else {
            continue;
        };
        let paired = device_props
            .get("Paired")
            .and_then(|v| v.0.as_any().downcast_ref::<bool>().copied())
            .unwrap_or(false);
        let bonded = device_props
            .get("Bonded")
            .and_then(|v| v.0.as_any().downcast_ref::<bool>().copied())
            .unwrap_or(false);
        return Ok((paired, bonded));
    }

    Err(format!("device {address} not found in bluez ObjectManager"))
}
