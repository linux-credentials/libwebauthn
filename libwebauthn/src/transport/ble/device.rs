use std::fmt;

use ::btleplug::api::Peripheral;
use async_trait::async_trait;
use hex::ToHex;
use tracing::{info, instrument};

use crate::transport::ble::error::BleError;
use crate::transport::device::Device;
use crate::transport::ChannelSettings;
use crate::webauthn::error::WebAuthnError;

use super::btleplug::manager::SupportedRevisions;
use super::btleplug::{supported_fido_revisions, FidoDevice as BtleplugFidoDevice};

use super::channel::BleChannel;
use super::{btleplug, Ble};

/// Checks if a Bluetooth adapter is available on the system.
pub async fn is_available() -> bool {
    btleplug::is_available().await
}

#[instrument]
pub async fn list_devices() -> Result<Vec<BleDevice>, BleError> {
    let devices: Vec<_> = btleplug::list_fido_devices()
        .await?
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

impl From<&BleDevice> for BtleplugFidoDevice {
    fn from(device: &BleDevice) -> Self {
        device.btleplug_device.clone()
    }
}

impl fmt::Display for BleDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.alias())
    }
}

#[async_trait]
impl<'d> Device<'d, Ble, BleChannel<'d>> for BleDevice {
    async fn channel(
        &'d mut self,
        settings: ChannelSettings,
    ) -> Result<BleChannel<'d>, WebAuthnError<BleError>> {
        let revisions = self
            .supported_revisions()
            .await
            .map_err(WebAuthnError::Transport)?;
        let channel = BleChannel::new(self, &revisions, settings).await?;
        Ok(channel)
    }

    // #[instrument(skip_all)]
    // async fn supported_protocols(&mut self) -> Result<SupportedProtocols, Error> {
    //     let revisions = self.supported_revisions().await?;
    //     Ok(revisions.into())
    // }
}

impl BleDevice {
    async fn supported_revisions(&mut self) -> Result<SupportedRevisions, BleError> {
        let revisions = match self.revisions {
            None => {
                let revisions = supported_fido_revisions(&self.btleplug_device.peripheral).await?;
                self.revisions = Some(revisions);
                revisions
            }
            Some(revisions) => revisions,
        };
        Ok(revisions)
    }
}
