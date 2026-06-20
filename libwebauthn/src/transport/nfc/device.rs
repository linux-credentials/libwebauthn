use async_trait::async_trait;
use std::collections::HashSet;
use std::fmt;
#[allow(unused_imports)]
use tracing::{debug, info, instrument, trace};

use crate::{
    transport::{device::Device, hid::HidDevice, Channel, ChannelSettings, UsbDeviceId},
    webauthn::error::WebAuthnError,
};

use super::channel::NfcChannel;
use super::error::NfcError;
#[cfg(feature = "nfc-backend-libnfc")]
use super::libnfc;
#[cfg(feature = "nfc-backend-pcsc")]
use super::pcsc;
use super::{Context, Nfc};

#[derive(Clone, Debug)]
enum DeviceInfo {
    #[cfg(feature = "nfc-backend-libnfc")]
    LibNfc(libnfc::Info),
    #[cfg(feature = "nfc-backend-pcsc")]
    Pcsc(pcsc::Info),
}

#[derive(Clone, Debug)]
pub struct NfcDevice {
    info: DeviceInfo,
}

impl fmt::Display for DeviceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            #[cfg(feature = "nfc-backend-libnfc")]
            DeviceInfo::LibNfc(info) => write!(f, "{}", info),
            #[cfg(feature = "nfc-backend-pcsc")]
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
    #[cfg(feature = "nfc-backend-libnfc")]
    pub fn new_libnfc(info: libnfc::Info) -> Self {
        NfcDevice {
            info: DeviceInfo::LibNfc(info),
        }
    }

    #[cfg(feature = "nfc-backend-pcsc")]
    pub fn new_pcsc(info: pcsc::Info) -> Self {
        NfcDevice {
            info: DeviceInfo::Pcsc(info),
        }
    }

    /// The USB (bus, address) backing this device, when it can be resolved.
    /// Performs blocking PC/SC I/O (a `Direct`-mode connect).
    pub fn usb_device_id(&self) -> Option<UsbDeviceId> {
        match &self.info {
            #[cfg(feature = "nfc-backend-pcsc")]
            DeviceInfo::Pcsc(info) => info.usb_device_id(),
            #[cfg(feature = "nfc-backend-libnfc")]
            DeviceInfo::LibNfc(_) => None,
        }
    }

    async fn channel_sync(
        &self,
        settings: ChannelSettings,
    ) -> Result<NfcChannel<Context>, WebAuthnError<NfcError>> {
        trace!("nfc channel {:?}", self);
        let mut channel: NfcChannel<Context> = match &self.info {
            #[cfg(feature = "nfc-backend-libnfc")]
            DeviceInfo::LibNfc(info) => info.channel(settings),
            #[cfg(feature = "nfc-backend-pcsc")]
            DeviceInfo::Pcsc(info) => info.channel(settings),
        }
        .map_err(WebAuthnError::Transport)?;

        channel.select_fido2().await?;
        Ok(channel)
    }
}

#[async_trait]
impl<'d> Device<'d, Nfc, NfcChannel<Context>> for NfcDevice {
    async fn channel(
        &'d mut self,
        settings: ChannelSettings,
    ) -> Result<NfcChannel<Context>, WebAuthnError<NfcError>> {
        self.channel_sync(settings).await
    }
}

async fn is_fido(device: &NfcDevice) -> bool {
    async fn inner(device: &NfcDevice) -> Result<bool, WebAuthnError<NfcError>> {
        let chan = device.channel_sync(ChannelSettings::default()).await?;
        let protocols = chan.supported_protocols().await?;
        Ok(protocols.fido2 || protocols.u2f)
    }

    inner(device).await.is_ok()
}

#[instrument]
/// Returns Ok(None) if no devices are found, otherwise returns
/// the first device found by either NFC-backend.
pub async fn get_nfc_device() -> Result<Option<NfcDevice>, WebAuthnError<NfcError>> {
    // See https://github.com/linux-credentials/libwebauthn/issues/154 for
    // why we only return the first found device here.
    // We'd otherwise need to deduplicate found devices here, as
    // we'll potentially have the same device discovered by
    // both backends and thus added multiple times to the list.
    let list_devices_fns = [
        #[cfg(feature = "nfc-backend-libnfc")]
        libnfc::list_devices,
        #[cfg(feature = "nfc-backend-pcsc")]
        pcsc::list_devices,
    ];

    for list_devices in list_devices_fns {
        for device in list_devices().map_err(WebAuthnError::Transport)? {
            if is_fido(&device).await {
                return Ok(Some(device));
            }
        }
    }

    Ok(None)
}

#[instrument]
pub fn is_nfc_available() -> bool {
    let mut available = false;
    #[cfg(feature = "nfc-backend-libnfc")]
    {
        available |= libnfc::is_nfc_available();
    }
    #[cfg(feature = "nfc-backend-pcsc")]
    {
        available |= pcsc::is_nfc_available();
    }

    available
}

/// Lists all NFC devices from the compiled backends, unfiltered. A failing
/// backend is skipped. Cross-backend duplicates are not removed.
#[instrument]
pub async fn list_devices() -> Vec<NfcDevice> {
    #[allow(unused_mut)]
    let mut devices = Vec::new();
    #[cfg(feature = "nfc-backend-libnfc")]
    if let Ok(found) = libnfc::list_devices() {
        devices.extend(found);
    }
    #[cfg(feature = "nfc-backend-pcsc")]
    if let Ok(found) = pcsc::list_devices() {
        devices.extend(found);
    }
    devices
}

/// Drops NFC devices that are the CCID face of a USB key already seen over HID,
/// matched by USB (bus, address). Does blocking PC/SC I/O per reader.
pub trait NfcDeviceSliceExt {
    fn without_hid_duplicates(&self, hid: &[HidDevice]) -> Vec<NfcDevice>;
}

impl NfcDeviceSliceExt for [NfcDevice] {
    fn without_hid_duplicates(&self, hid: &[HidDevice]) -> Vec<NfcDevice> {
        let hid_ids: HashSet<UsbDeviceId> =
            hid.iter().filter_map(HidDevice::usb_device_id).collect();
        let nfc_ids: Vec<Option<UsbDeviceId>> = self.iter().map(NfcDevice::usb_device_id).collect();
        self.iter()
            .zip(dedup_keep_mask(&nfc_ids, &hid_ids))
            .filter(|&(_, keep)| keep)
            .map(|(device, _)| device.clone())
            .collect()
    }
}

/// Pure dedup core, unit-testable without hardware.
fn dedup_keep_mask(nfc_ids: &[Option<UsbDeviceId>], hid_ids: &HashSet<UsbDeviceId>) -> Vec<bool> {
    nfc_ids
        .iter()
        .map(|id| match id {
            Some(id) => !hid_ids.contains(id),
            None => true,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_keeps_non_duplicates_and_unknown() {
        let a = UsbDeviceId { bus: 1, address: 8 };
        let b = UsbDeviceId { bus: 1, address: 9 };
        let nfc_ids = [Some(a), Some(b), None];
        let hid_ids: HashSet<UsbDeviceId> = [a].into_iter().collect();

        assert_eq!(dedup_keep_mask(&nfc_ids, &hid_ids), vec![false, true, true]);
    }
}
