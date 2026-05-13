pub mod connection;
pub mod device;
pub mod error;
pub mod gatt;
pub mod manager;
pub(crate) mod pairing;

pub use connection::Connection;
pub use device::FidoDevice;
pub use error::Error;
pub use manager::{
    connect, is_available, list_fido_devices, start_discovery_for_service_data,
    supported_fido_revisions,
};
