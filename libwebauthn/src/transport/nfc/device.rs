use async_trait::async_trait;
use std::fmt;
#[allow(unused_imports)]
use tracing::{debug, info, instrument, trace};

use crate::webauthn::error::Error;
use crate::transport::device::Device;

use super::channel::NfcChannel;
#[cfg(feature = "libnfc")]
use super::libnfc;
#[cfg(feature = "pcsc")]
use super::pcsc;
use super::{Context, Nfc};

#[derive(Debug)]
enum DeviceInfo {
    #[cfg(feature = "libnfc")]
    LibNfc(libnfc::Info),
    #[cfg(feature = "pcsc")]
    Pcsc(pcsc::Info),
}

#[derive(Debug)]
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

    fn channel_sync<'d>(
        &'d self,
    ) -> Result<NfcChannel<Context>, Error> {
        trace!("nfc channel {:?}", self);
        let mut channel: NfcChannel<Context> = match &self.info
        {
            #[cfg(feature = "libnfc")]
            DeviceInfo::LibNfc(info) => info.channel(),
            #[cfg(feature = "pcsc")]
            DeviceInfo::Pcsc(info) => info.channel(),
        }?;

        channel.select_fido2()?;

        Ok(channel)
    }
}

#[async_trait]
impl<'d> Device<'d, Nfc, NfcChannel<Context>> for NfcDevice {
    async fn channel(
        &'d mut self,
    ) -> Result<NfcChannel<Context>, Error> {
        self.channel_sync()
    }
}

fn is_fido<Ctx>(device: &NfcDevice) -> bool
where
    Ctx: fmt::Debug + fmt::Display + Copy + Send + Sync,
{
    fn inner<Ctx>(device: &NfcDevice) -> Result<bool, Error>
    where
        Ctx: fmt::Debug + fmt::Display + Copy + Send + Sync,
    {
        let mut chan = device.channel_sync()?;
        let _ = chan.select_fido2()?;
        Ok(true)
    }

    inner::<Ctx>(device).is_ok()
}

#[instrument]
pub async fn list_devices() -> Result<Vec<NfcDevice>, Error> {
    let mut all_devices = Vec::new();
    let list_devices_fns = [
        #[cfg(feature = "libnfc")]
        libnfc::list_devices,
        #[cfg(feature = "pcsc")]
        pcsc::list_devices,
    ];

    for list_devices in list_devices_fns {
        let mut devices = list_devices()?
            .into_iter()
            .filter(|e| is_fido::<Context>(&e))
            .collect::<Vec<NfcDevice>>();
        all_devices.append(&mut devices);
    }

    Ok(all_devices)
}
