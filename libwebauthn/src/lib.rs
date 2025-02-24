pub mod fido;
pub mod management;
pub mod ops;
pub mod pin;
pub mod proto;
pub mod transport;
pub mod u2f;
pub mod webauthn;

#[macro_use]
extern crate num_derive;

#[macro_use]
extern crate bitflags;

macro_rules! unwrap_field {
    ($field:expr) => {{
        if let Some(f) = $field {
            f
        } else {
            tracing::error!(
                "Device response did not contain expected field: {}",
                stringify!($field)
            );
            return Err(Error::Platform(PlatformError::InvalidDeviceResponse));
        }
    }};
}
pub(crate) use unwrap_field;

#[derive(Debug)]
pub enum Transport {
    Usb,
    Ble,
}

pub fn available_transports() -> Vec<Transport> {
    vec![Transport::Usb, Transport::Ble]
}
