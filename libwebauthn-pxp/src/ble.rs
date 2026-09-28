//! Minimal btleplug scan for the CMHD's BLE advertisement. Only service data
//! and the peripheral's properties are needed; no GATT connection is made.
use std::collections::HashMap;

use btleplug::api::{Central as _, CentralEvent, Manager as _, Peripheral as _};
use btleplug::api::{PeripheralProperties, ScanFilter};
use btleplug::platform::{Adapter, Manager, Peripheral, PeripheralId};
use futures::{Stream, StreamExt};
use tracing::{debug, instrument, trace, warn, Level};
use uuid::Uuid;

use crate::error::CableError;

/// TODO(#86): Support multiple adapters.
async fn get_adapter() -> Result<Adapter, CableError> {
    let manager = Manager::new()
        .await
        .or(Err(CableError::TransportUnavailable))?;
    manager
        .adapters()
        .await
        .or(Err(CableError::TransportUnavailable))?
        .into_iter()
        .next()
        .ok_or(CableError::TransportUnavailable)
}

async fn on_peripheral_service_data(
    adapter: &Adapter,
    id: &PeripheralId,
    uuids: &[Uuid],
    service_data: HashMap<Uuid, Vec<u8>>,
) -> Option<(Peripheral, Vec<u8>)> {
    let data = uuids.iter().find_map(|uuid| service_data.get(uuid))?;
    trace!(?id, ?data, "Found service data");

    let Ok(peripheral) = adapter.peripheral(id).await else {
        warn!(?id, "Could not get peripheral");
        return None;
    };

    debug!({ ?id, ?data }, "Found service data for peripheral");
    Some((peripheral, data.to_owned()))
}

/// Scans for peripherals advertising service data on any of `uuids`. Returns
/// the adapter, so the caller can stop the scan, and the matching stream.
#[instrument(level = Level::DEBUG, skip_all)]
pub(crate) async fn start_discovery_for_service_data(
    uuids: &[Uuid],
) -> Result<(Adapter, impl Stream<Item = (Peripheral, Vec<u8>)> + use<'_>), CableError> {
    let adapter = get_adapter().await?;
    let events = adapter
        .events()
        .await
        .or(Err(CableError::TransportUnavailable))?;

    adapter
        .start_scan(ScanFilter::default())
        .await
        .or(Err(CableError::TransportUnavailable))?;

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

    Ok((adapter, stream))
}

pub(crate) async fn get_properties(
    peripheral: &Peripheral,
) -> Result<Option<PeripheralProperties>, CableError> {
    peripheral
        .properties()
        .await
        .or(Err(CableError::TransportUnavailable))
}
