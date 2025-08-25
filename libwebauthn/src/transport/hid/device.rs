use super::channel::HidChannel;
use super::Hid;
use async_trait::async_trait;
use hidapi::DeviceInfo;
use hidapi::HidApi;
use std::fmt;
#[allow(unused_imports)]
use tracing::{debug, info, instrument};

use crate::transport::error::TransportError;
use crate::transport::Device;
use crate::webauthn::error::Error;

#[derive(Debug, Clone)]
pub struct HidDevice {
    pub backend: HidBackendDevice,
}

#[derive(Debug, Clone)]
pub enum HidBackendDevice {
    HidApiDevice(DeviceInfo),
    #[cfg(test)]
    VirtualDevice,
}

impl From<&DeviceInfo> for HidDevice {
    fn from(hidapi_device: &DeviceInfo) -> Self {
        Self {
            backend: HidBackendDevice::HidApiDevice(hidapi_device.clone()),
        }
    }
}

impl fmt::Display for HidDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.backend {
            HidBackendDevice::HidApiDevice(dev) => write!(
                f,
                "{:} {:} (r{:?})",
                dev.manufacturer_string().unwrap(),
                dev.product_string().unwrap(),
                dev.release_number()
            ),
            #[cfg(test)]
            HidBackendDevice::VirtualDevice => write!(f, "virtual fido-authenticator"),
        }
    }
}

pub(crate) fn get_hidapi() -> Result<HidApi, Error> {
    HidApi::new().or(Err(Error::Transport(TransportError::TransportUnavailable)))
}

#[instrument]
pub async fn list_devices() -> Result<Vec<HidDevice>, Error> {
    let devices: Vec<_> = get_hidapi()?
        .device_list()
        .filter(|device| device.usage_page() == 0xF1D0)
        .filter(|device| device.usage() == 0x0001)
        .map(|device| device.into())
        .collect();
    info!({ count = devices.len() }, "Listing available HID devices");
    debug!(?devices);
    Ok(devices)
}

#[cfg(test)]
pub fn get_virtual_device() -> HidDevice {
    HidDevice::new_virtual()
}

#[cfg(test)]
impl HidDevice {
    pub fn new_virtual() -> Self {
        Self {
            backend: HidBackendDevice::VirtualDevice,
        }
    }
}

#[async_trait]
impl<'d> Device<'d, Hid, HidChannel<'d>> for HidDevice {
    async fn channel(&'d mut self) -> Result<HidChannel<'d>, Error> {
        let channel = HidChannel::new(self).await?;
        Ok(channel)
    }

    // async fn supported_protocols(&mut self) -> Result<SupportedProtocols, Error> {
    //     let channel = self.channel().await?;
    //     channel.supported_protocols().await
    // }
}
