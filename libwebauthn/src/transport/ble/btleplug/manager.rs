use std::collections::HashMap;

use btleplug::api::bleuuid::uuid_from_u16;
use btleplug::api::{
    Central as _, Manager as _, Peripheral as _, PeripheralProperties, ScanFilter,
};
use btleplug::platform::{Adapter, Manager, Peripheral};
use tracing::{debug, info, instrument, Level};
use uuid::Uuid;

use super::device::FidoEndpoints;
use super::gatt::get_gatt_characteristic;
use super::{Connection, Error, FidoDevice};
use crate::fido::{FidoProtocol, FidoRevision};

pub const FIDO_PROFILE_UUID: Uuid = uuid_from_u16(0xFFFD);

pub const FIDO_CONTROL_POINT_UUID: &str = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb";
pub const FIDO_STATUS_UUID: &str = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb";
pub const FIDO_CONTROL_POINT_LENGTH_UUID: &str = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb";
pub const FIDO_REVISION_BITFIELD_UUID: &str = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb";

#[derive(Debug, Copy, Clone)]
pub struct SupportedRevisions {
    pub u2fv11: bool,
    pub u2fv12: bool,
    pub v2: bool,
}

impl SupportedRevisions {
    pub fn select_protocol(&self, protocol: FidoProtocol) -> Option<FidoRevision> {
        match protocol {
            FidoProtocol::FIDO2 => {
                if self.v2 {
                    Some(FidoRevision::V2)
                } else {
                    None
                }
            }
            FidoProtocol::U2F => {
                if self.u2fv12 {
                    Some(FidoRevision::U2fv12)
                } else if self.u2fv11 {
                    Some(FidoRevision::U2fv11)
                } else {
                    None
                }
            }
        }
    }
}

#[instrument(level = Level::DEBUG, skip_all)]
pub async fn start_discovery(uuids: &[Uuid]) -> Result<(), Error> {
    let adapter = get_adapter().await?;
    let scan_filter = ScanFilter {
        services: uuids.to_vec(),
    };

    adapter
        .start_scan(scan_filter)
        .await
        .or(Err(Error::ConnectionFailed))
}

/// TODO(#86): Support multiple adapters.
async fn get_adapter() -> Result<Adapter, Error> {
    let manager = Manager::new().await.or(Err(Error::Unavailable))?;
    manager
        .adapters()
        .await
        .or(Err(Error::Unavailable))?
        .into_iter()
        .nth(0)
        .ok_or(Error::PoweredOff)
}

async fn discover_properties(
    peripherals: Vec<Peripheral>,
) -> Result<Vec<(Peripheral, PeripheralProperties)>, Error> {
    let mut result = vec![];
    for peripheral in peripherals {
        let properties = peripheral
            .properties()
            .await
            .or(Err(Error::ConnectionFailed))?;
        if let Some(properties) = properties {
            result.push((peripheral, properties));
        }
    }
    Ok(result)
}

#[instrument(level = Level::DEBUG, skip_all)]
pub async fn list_fido_devices() -> Result<Vec<FidoDevice>, Error> {
    let adapter = get_adapter().await?;
    let peripherals: Vec<Peripheral> = adapter
        .peripherals()
        .await
        .or(Err(Error::ConnectionFailed))?
        .into_iter()
        .filter(|p| {
            p.services()
                .iter()
                .find(|s| s.uuid == FIDO_PROFILE_UUID)
                .is_some()
        })
        .collect();
    let with_properties = discover_properties(peripherals)
        .await?
        .into_iter()
        .map(|(peripheral, properties)| FidoDevice {
            peripheral,
            properties,
        })
        .collect();
    Ok(with_properties)
}

#[instrument(level = Level::DEBUG, skip_all)]
pub async fn list_devices_with_service_data(
    service_uuid: Uuid,
) -> Result<HashMap<FidoDevice, Vec<u8>>, Error> {
    let adapter = get_adapter().await?;
    let peripherals = adapter
        .peripherals()
        .await
        .or(Err(Error::ConnectionFailed))?;
    for peripheral in &peripherals {
        // TODO: parallelize this
        peripheral
            .discover_services()
            .await
            .or(Err(Error::ConnectionFailed))?;
    }
    let with_properties = discover_properties(peripherals).await?;
    Ok(with_properties
        .into_iter()
        .filter_map(
            |(peripheral, properties)| match properties.service_data.get(&service_uuid) {
                Some(service_data) => {
                    let device = FidoDevice {
                        peripheral,
                        properties: properties.to_owned(),
                    };
                    Some((device, service_data.to_owned()))
                }
                None => None,
            },
        )
        .collect())
}

pub async fn supported_fido_revisions(
    peripheral: &Peripheral,
) -> Result<SupportedRevisions, Error> {
    let services = discover_services(peripheral).await?;
    let revision = peripheral
        .read(&services.service_revision_bitfield)
        .await
        .or(Err(Error::ConnectionFailed))?;
    let bitfield = revision.iter().next().ok_or(Error::OperationFailed)?;
    debug!(?revision, "Supported revision bitfield");

    let supported = SupportedRevisions {
        u2fv11: bitfield & FidoRevision::U2fv11 as u8 != 0x00,
        u2fv12: bitfield & FidoRevision::U2fv12 as u8 != 0x00,
        v2: bitfield & FidoRevision::V2 as u8 != 0x00,
    };
    info!(?supported, "Device reported supporting FIDO revisions");
    Ok(supported)
}

/// Connect, discover FIDO services on this device, and
/// select the FIDO revision to be used.
pub async fn connect(
    peripheral: &Peripheral,
    revision: &FidoRevision,
) -> Result<Connection, Error> {
    peripheral
        .connect()
        .await
        .or(Err(Error::ConnectionFailed))?;
    peripheral
        .discover_services()
        .await
        .or(Err(Error::ConnectionFailed))?;
    let services = discover_services(peripheral).await?;
    Connection::new(peripheral, &services, revision).await
}

async fn discover_services(peripheral: &Peripheral) -> Result<FidoEndpoints, Error> {
    let control_point_uuid = Uuid::parse_str(FIDO_CONTROL_POINT_UUID).unwrap();
    let control_point = get_gatt_characteristic(peripheral, control_point_uuid)?;

    let control_point_length_uuid = Uuid::parse_str(FIDO_CONTROL_POINT_LENGTH_UUID).unwrap();
    let control_point_length = get_gatt_characteristic(peripheral, control_point_length_uuid)?;

    let status_uuid = Uuid::parse_str(FIDO_STATUS_UUID).unwrap();
    let status = get_gatt_characteristic(peripheral, status_uuid)?;

    let service_revision_bitfield_uuid = Uuid::parse_str(FIDO_REVISION_BITFIELD_UUID).unwrap();
    let service_revision_bitfield =
        get_gatt_characteristic(peripheral, service_revision_bitfield_uuid)?;

    Ok(FidoEndpoints {
        control_point,
        control_point_length,
        status,
        service_revision_bitfield,
    })
}
