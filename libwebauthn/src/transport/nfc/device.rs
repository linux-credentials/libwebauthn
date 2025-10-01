use async_trait::async_trait;
use std::fmt;
#[allow(unused_imports)]
use tracing::{debug, info, instrument, trace};

use crate::{
    transport::{device::Device, Channel},
    webauthn::Error,
};

use super::channel::NfcChannel;
#[cfg(feature = "libnfc")]
use super::libnfc;
#[cfg(feature = "pcsc")]
use super::pcsc;
use super::{Context, Nfc};

#[derive(Clone, Debug)]
enum DeviceInfo {
    #[cfg(feature = "libnfc")]
    LibNfc(libnfc::Info),
    #[cfg(feature = "pcsc")]
    Pcsc(pcsc::Info),
}

#[derive(Clone, Debug)]
pub struct NfcDevice {
    info: DeviceInfo,
}

impl fmt::Display for DeviceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            #[cfg(feature = "libnfc")]
            DeviceInfo::LibNfc(info) => write!(f, "{}", info),
            #[cfg(feature = "pcsc")]
            DeviceInfo::Pcsc(info) => write!(f, "{}", info),
        }
    }
}

impl fmt::Display for NfcDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.info)
    }
}

impl NfcDevice {
    #[cfg(feature = "libnfc")]
    pub fn new_libnfc(info: libnfc::Info) -> Self {
        NfcDevice {
            info: DeviceInfo::LibNfc(info),
        }
    }

    #[cfg(feature = "pcsc")]
    pub fn new_pcsc(info: pcsc::Info) -> Self {
        NfcDevice {
            info: DeviceInfo::Pcsc(info),
        }
    }

    async fn channel_sync(&self) -> Result<NfcChannel<Context>, Error> {
        trace!("nfc channel {:?}", self);
        let mut channel: NfcChannel<Context> = match &self.info {
            #[cfg(feature = "libnfc")]
            DeviceInfo::LibNfc(info) => info.channel(),
            #[cfg(feature = "pcsc")]
            DeviceInfo::Pcsc(info) => info.channel(),
        }?;

        channel.select_fido2().await?;
        Ok(channel)
    }
}

#[async_trait]
impl<'d> Device<'d, Nfc, NfcChannel<Context>> for NfcDevice {
    async fn channel(&'d mut self) -> Result<NfcChannel<Context>, Error> {
        self.channel_sync().await
    }
}

async fn is_fido<Ctx>(device: &NfcDevice) -> bool
where
    Ctx: fmt::Debug + fmt::Display + Copy + Send + Sync,
{
    async fn inner<Ctx>(device: &NfcDevice) -> Result<bool, Error>
    where
        Ctx: fmt::Debug + fmt::Display + Copy + Send + Sync,
    {
        let chan = device.channel_sync().await?;
        // We fill the struct within channel_sync() and the call cannot fail for NFC,
        // so unwrap is fine here
        let protocols = chan.supported_protocols().await.unwrap();
        Ok(protocols.fido2 || protocols.u2f)
    }

    inner::<Ctx>(device).await.is_ok()
}

#[instrument]
pub async fn list_devices() -> Result<Vec<NfcDevice>, Error> {
    let mut all_devices = Vec::new();
    // TODO: Either only allow one backend, OR deduplicate found devices here!
    //       Otherwise, we'll potentially have the same device discovered by
    //       both backends and thus added multiple times to the list.
    let list_devices_fns = [
        #[cfg(feature = "libnfc")]
        libnfc::list_devices,
        #[cfg(feature = "pcsc")]
        pcsc::list_devices,
    ];

    for list_devices in list_devices_fns {
        for device in list_devices()? {
            if is_fido::<Context>(&device).await {
                all_devices.push(device);
            }
        }
    }

    Ok(all_devices)
}
