//! Minimal btleplug scan for the CMHD's BLE advertisement. Only service data
//! and the peripheral's properties are needed; no GATT connection is made.
use std::collections::HashMap;

use btleplug::api::{Central as _, CentralEvent, Manager as _, Peripheral as _};
use btleplug::api::{PeripheralProperties, ScanFilter};
use btleplug::platform::{Adapter, Manager, Peripheral, PeripheralId};
use futures::{Stream, StreamExt};
use tracing::{debug, instrument, trace, warn, Level};
use uuid::Uuid;

use crate::error::PxpError;

/// TODO(#86): Support multiple adapters.
async fn get_adapter() -> Result<Adapter, PxpError> {
    let manager = Manager::new()
        .await
        .or(Err(PxpError::TransportUnavailable))?;
    manager
        .adapters()
        .await
        .or(Err(PxpError::TransportUnavailable))?
        .into_iter()
        .next()
        .ok_or(PxpError::TransportUnavailable)
}

async fn on_peripheral_service_data(
    adapter: &Adapter,
    id: &PeripheralId,
    uuids: &[Uuid],
    service_data: HashMap<Uuid, Vec<u8>>,
) -> Option<(Peripheral, Vec<u8>)> {
    let data = uuids.iter().find_map(|uuid| service_data.get(uuid))?;
    trace!({ ?id, ?data }, "Found service data");

    let Ok(peripheral) = adapter.peripheral(id).await else {
        warn!("Could not get peripheral");
        return None;
    };

    debug!({ ?id, len = data.len() }, "Found service data for peripheral");
    Some((peripheral, data.to_owned()))
}

/// A discovery is abandoned whenever the caller is cancelled or returns early,
/// which would otherwise leave the adapter scanning for the lifetime of the
/// process.
pub(crate) struct ScanGuard(Option<Adapter>);

impl ScanGuard {
    /// Stops the scan and waits for the adapter to acknowledge it.
    pub(crate) async fn stop(mut self) {
        let Some(adapter) = self.0.take() else {
            return;
        };
        if let Err(e) = adapter.stop_scan().await {
            warn!(?e, "Failed to stop BLE scan");
        }
    }
}

impl Drop for ScanGuard {
    fn drop(&mut self) {
        // We start the scan but don't block on it being stopped.
        let Some(adapter) = self.0.take() else {
            return;
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    if let Err(e) = adapter.stop_scan().await {
                        warn!(?e, "Failed to stop BLE scan");
                    }
                });
            }
            Err(e) => warn!(?e, "No runtime available to stop BLE scan"),
        }
    }
}

/// Scans for peripherals advertising service data on any of `uuids`. Returns
/// a guard that stops the scan, and the matching stream.
#[instrument(level = Level::DEBUG, skip_all)]
pub(crate) async fn start_discovery_for_service_data(
    uuids: &[Uuid],
) -> Result<
    (
        ScanGuard,
        impl Stream<Item = (Peripheral, Vec<u8>)> + use<'_>,
    ),
    PxpError,
> {
    let adapter = get_adapter().await?;
    let events = adapter
        .events()
        .await
        .or(Err(PxpError::TransportUnavailable))?;

    let scan_guard = ScanGuard(Some(adapter.clone()));

    adapter
        .start_scan(ScanFilter::default())
        .await
        .or(Err(PxpError::TransportUnavailable))?;

    let scan_adapter = adapter.clone();
    let stream = events.filter_map(move |event| {
        let adapter = scan_adapter.clone();
        async move {
            match event {
                CentralEvent::ServiceDataAdvertisement { id, service_data } => {
                    on_peripheral_service_data(&adapter, &id, uuids, service_data).await
                }
                _ => None,
            }
        }
    });

    Ok((scan_guard, stream))
}

pub(crate) async fn get_properties(
    peripheral: &Peripheral,
) -> Result<Option<PeripheralProperties>, PxpError> {
    peripheral
        .properties()
        .await
        .or(Err(PxpError::TransportUnavailable))
}
