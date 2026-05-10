use btleplug::api::{CharPropFlags, Characteristic, Peripheral as _, WriteType};
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

/// Picks a `WriteType` from a characteristic's advertised GATT properties.
///
/// `fidoControlPoint` and `fidoServiceRevisionBitfield` are Write
/// characteristics per CTAP 2.2 §11.4; only downgrade to WithoutResponse
/// when that is the sole property advertised.
pub fn write_type_for(characteristic: &Characteristic) -> WriteType {
    if characteristic.properties.contains(CharPropFlags::WRITE) {
        WriteType::WithResponse
    } else if characteristic
        .properties
        .contains(CharPropFlags::WRITE_WITHOUT_RESPONSE)
    {
        WriteType::WithoutResponse
    } else {
        WriteType::WithResponse
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn make_characteristic(properties: CharPropFlags) -> Characteristic {
        Characteristic {
            uuid: Uuid::nil(),
            service_uuid: Uuid::nil(),
            properties,
            descriptors: BTreeSet::new(),
        }
    }

    #[test]
    fn write_type_prefers_with_response_when_write_property_set() {
        let c = make_characteristic(CharPropFlags::WRITE);
        assert_eq!(write_type_for(&c), WriteType::WithResponse);
    }

    #[test]
    fn write_type_uses_without_response_when_only_write_without_response() {
        let c = make_characteristic(CharPropFlags::WRITE_WITHOUT_RESPONSE);
        assert_eq!(write_type_for(&c), WriteType::WithoutResponse);
    }

    #[test]
    fn write_type_prefers_with_response_when_both_properties_set() {
        let c = make_characteristic(CharPropFlags::WRITE | CharPropFlags::WRITE_WITHOUT_RESPONSE);
        assert_eq!(write_type_for(&c), WriteType::WithResponse);
    }

    #[test]
    fn write_type_defaults_to_with_response_when_no_property_set() {
        let c = make_characteristic(CharPropFlags::empty());
        assert_eq!(write_type_for(&c), WriteType::WithResponse);
    }

    #[test]
    fn write_type_ignores_unrelated_properties() {
        let c = make_characteristic(CharPropFlags::READ | CharPropFlags::NOTIFY);
        assert_eq!(write_type_for(&c), WriteType::WithResponse);
    }
}
