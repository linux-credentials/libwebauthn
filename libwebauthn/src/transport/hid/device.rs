use super::channel::HidChannel;
use super::Hid;
use async_trait::async_trait;
use hidapi::DeviceInfo;
use hidapi::HidApi;
use std::fmt;
#[cfg(feature = "virt")]
use std::sync::{Arc, Mutex};
#[allow(unused_imports)]
use tracing::{debug, info, instrument};

#[cfg(feature = "virt")]
use super::framing::HidMessage;
use crate::transport::hid::error::HidError;
use crate::transport::usb::{usb_id_from_hidraw, UsbDeviceId};
use crate::transport::{ChannelSettings, Device};
use crate::webauthn::error::WebAuthnError;

#[cfg(feature = "virt")]
pub trait HidPipeBackend: fmt::Debug + Send {
    fn send(&mut self, msg: &HidMessage);
    fn recv(&mut self) -> HidMessage;
}

#[derive(Debug, Clone)]
pub struct HidDevice {
    pub backend: HidBackendDevice,
}

#[derive(Debug, Clone)]
pub enum HidBackendDevice {
    HidApiDevice(DeviceInfo),
    #[cfg(feature = "virt")]
    VirtualDevice(Arc<Mutex<dyn HidPipeBackend>>),
}

impl From<&DeviceInfo> for HidDevice {
    fn from(hidapi_device: &DeviceInfo) -> Self {
        Self {
            backend: HidBackendDevice::HidApiDevice(hidapi_device.clone()),
        }
    }
}

impl HidDevice {
    /// The USB (bus, address) backing this key, when it can be resolved.
    pub fn usb_device_id(&self) -> Option<UsbDeviceId> {
        match &self.backend {
            HidBackendDevice::HidApiDevice(info) => usb_id_from_hidraw(info.path()),
            #[cfg(feature = "virt")]
            HidBackendDevice::VirtualDevice(_) => None,
        }
    }
}

impl fmt::Display for HidDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.backend {
            HidBackendDevice::HidApiDevice(dev) => {
                let manufacturer = dev.manufacturer_string().unwrap_or_default();
                let product = dev.product_string().unwrap_or_default();
                let name = [manufacturer, product].join(" ");
                write!(f, "{} (r{:?})", name.trim(), dev.release_number())
            }
            #[cfg(feature = "virt")]
            HidBackendDevice::VirtualDevice(_) => write!(f, "virtual fido-authenticator"),
        }
    }
}

pub(crate) fn get_hidapi() -> Result<HidApi, HidError> {
    HidApi::new().map_err(HidError::ApiInit)
}

#[instrument]
pub async fn list_devices() -> Result<Vec<HidDevice>, HidError> {
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

#[cfg(feature = "virt")]
pub fn virtual_device<B: HidPipeBackend + 'static>(backend: B) -> HidDevice {
    HidDevice {
        backend: HidBackendDevice::VirtualDevice(Arc::new(Mutex::new(backend))),
    }
}

#[async_trait]
impl<'d> Device<'d, Hid, HidChannel<'d>> for HidDevice {
    async fn channel(
        &'d mut self,
        settings: ChannelSettings,
    ) -> Result<HidChannel<'d>, WebAuthnError<HidError>> {
        let channel = HidChannel::new(self, settings).await?;
        Ok(channel)
    }

    // async fn supported_protocols(&mut self) -> Result<SupportedProtocols, Error> {
    //     let channel = self.channel().await?;
    //     channel.supported_protocols().await
    // }
}
