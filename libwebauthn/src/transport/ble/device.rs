use std::fmt;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::{info, instrument};

use crate::transport::device::Device;
use crate::transport::error::{Error, TransportError};
use crate::StateUpdate;

use super::bluez::manager::SupportedRevisions;
use super::bluez::{supported_fido_revisions, FidoDevice as BlueZFidoDevice};

use super::channel::BleChannel;
use super::{bluez, Ble};

#[instrument]
pub async fn list_devices() -> Result<Vec<BleDevice>, Error> {
    let devices: Vec<_> = bluez::list_devices()
        .await
        .or(Err(Error::Transport(TransportError::TransportUnavailable)))?
        .iter()
        .map(|bluez_device| bluez_device.into())
        .collect();
    info!({ count = devices.len() }, "Listing available BLE devices");
    Ok(devices)
}

#[derive(Debug, Clone)]
pub struct BleDevice {
    pub bluez_device: BlueZFidoDevice,
    pub revisions: Option<SupportedRevisions>,
}

impl BleDevice {
    pub fn alias(&self) -> String {
        self.bluez_device.alias.clone()
    }

    pub fn is_connected(&self) -> bool {
        self.bluez_device.is_connected
    }

    pub fn is_paired(&self) -> bool {
        self.bluez_device.is_paired
    }
}

impl From<&BlueZFidoDevice> for BleDevice {
    fn from(bluez_device: &BlueZFidoDevice) -> Self {
        Self {
            bluez_device: bluez_device.clone(),
            revisions: None,
        }
    }
}

impl Into<BlueZFidoDevice> for &BleDevice {
    fn into(self) -> BlueZFidoDevice {
        self.bluez_device.clone()
    }
}

impl fmt::Display for BleDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.alias())
    }
}

#[async_trait]
impl<'d> Device<'d, Ble, BleChannel<'d>> for BleDevice {
    async fn channel(&'d mut self) -> Result<(BleChannel<'d>, mpsc::Receiver<StateUpdate>), Error> {
        let revisions = self.supported_revisions().await?;
        let (send, recv) = mpsc::channel(1);
        let channel = BleChannel::new(self, &revisions, send).await?;
        Ok((channel, recv))
    }

    // #[instrument(skip_all)]
    // async fn supported_protocols(&mut self) -> Result<SupportedProtocols, Error> {
    //     let revisions = self.supported_revisions().await?;
    //     Ok(revisions.into())
    // }
}

impl BleDevice {
    async fn supported_revisions(&mut self) -> Result<SupportedRevisions, Error> {
        let revisions = match self.revisions {
            None => {
                let revisions = supported_fido_revisions(&self.bluez_device)
                    .await
                    .or(Err(Error::Transport(TransportError::NegotiationFailed)))?;
                self.revisions = Some(revisions);
                revisions
            }
            Some(revisions) => revisions,
        };
        Ok(revisions)
    }
}
