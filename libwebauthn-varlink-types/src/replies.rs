use serde::{Deserialize, Serialize};
use zlink::introspect;

/// Reply to `IsAvailable`.
#[derive(Debug, Clone, Serialize, Deserialize, introspect::Type)]
pub struct VarlinkAvailabilityReply {
    pub available: bool,
}

/// Reply to `FutureDeviceConnection`.
#[derive(Debug, Clone, Serialize, Deserialize, introspect::Type)]
pub struct VarlinkQrCodeReply {
    pub qr_contents: String,
}
