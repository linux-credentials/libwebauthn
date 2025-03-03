pub mod connection;
pub mod device;
pub mod error;
pub mod gatt;
pub mod manager;

pub use connection::Connection;
pub use device::FidoDevice;
pub use error::Error;
pub use manager::{
    connect, list_devices_with_service_data, list_fido_devices, start_discovery,
    supported_fido_revisions,
};
