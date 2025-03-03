use std::hash::Hash;

use btleplug::{
    api::{Characteristic, Peripheral as _, PeripheralProperties},
    platform::Peripheral,
};

#[derive(Debug, Clone)]
pub struct FidoDevice {
    pub peripheral: Peripheral,
    pub properties: PeripheralProperties,
}

impl PartialEq for FidoDevice {
    fn eq(&self, other: &Self) -> bool {
        self.peripheral.id() == other.peripheral.id()
    }
}

impl Eq for FidoDevice {}

impl Hash for FidoDevice {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.peripheral.id().hash(state);
    }
}

#[derive(Debug, Clone)]
pub struct FidoEndpoints {
    pub control_point: Characteristic,
    pub control_point_length: Characteristic,
    pub status: Characteristic,
    pub service_revision_bitfield: Characteristic,
}
