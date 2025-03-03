use btleplug::api::{Characteristic, Peripheral as _};
use btleplug::platform::Peripheral;
use uuid::Uuid;

use super::Error;

pub fn get_gatt_characteristic(
    peripheral: &Peripheral,
    uuid: Uuid,
) -> Result<Characteristic, Error> {
    peripheral
        .characteristics()
        .iter()
        .find(|c| c.uuid == uuid)
        .map(ToOwned::to_owned)
        .ok_or(Error::ConnectionFailed)
}
