use std::fmt;

use ::btleplug::api::Peripheral;
use async_trait::async_trait;
use hex::ToHex;
use tokio::sync::mpsc;
use tracing::{info, instrument};

use crate::transport::device::Device;
use crate::transport::error::{Error, TransportError};
use crate::UxUpdate;

use super::btleplug::manager::SupportedRevisions;
use super::btleplug::{supported_fido_revisions, FidoDevice as BtleplugFidoDevice};

use super::channel::BleChannel;
use super::{btleplug, Ble};

#[instrument]
pub async fn list_devices() -> Result<Vec<BleDevice>, Error> {
    let devices: Vec<_> = btleplug::list_fido_devices()
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
    pub btleplug_device: BtleplugFidoDevice,
    pub revisions: Option<SupportedRevisions>,
}

impl BleDevice {
    pub fn alias(&self) -> String {
        match &self.btleplug_device.properties.local_name {
            Some(local_name) => local_name.clone(),
            None => self.btleplug_device.properties.address.encode_hex(),
        }
    }

    pub async fn is_connected(&self) -> bool {
        self.btleplug_device
            .peripheral
            .is_connected()
            .await
            .unwrap_or(false)
    }
}

impl From<&BtleplugFidoDevice> for BleDevice {
    fn from(btleplug_device: &BtleplugFidoDevice) -> Self {
        Self {
            btleplug_device: btleplug_device.clone(),
            revisions: None,
        }
    }
}

impl Into<BtleplugFidoDevice> for &BleDevice {
    fn into(self) -> BtleplugFidoDevice {
        self.btleplug_device.clone()
    }
}

impl fmt::Display for BleDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.alias())
    }
}

#[async_trait]
impl<'d> Device<'d, Ble, BleChannel<'d>> for BleDevice {
    async fn channel(&'d mut self) -> Result<(BleChannel<'d>, mpsc::Receiver<UxUpdate>), Error> {
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
                let revisions = supported_fido_revisions(&self.btleplug_device.peripheral)
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
