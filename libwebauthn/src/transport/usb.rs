//! Identifies a physical USB device by its (bus, address), which is shared by
//! all of its interfaces. Lets us recognise one key seen over both HID and PC/SC.

/// A physical USB device, identified by its (bus, address) pair.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct UsbDeviceId {
    pub bus: u8,
    pub address: u8,
}

impl UsbDeviceId {
    /// Decodes a `SCARD_ATTR_CHANNEL_ID` DWORD (USB marker `0x0020`, then `bus << 8 | address`).
    #[cfg_attr(not(feature = "nfc-backend-pcsc"), allow(dead_code))]
    pub(crate) fn from_channel_id(dword: u32) -> Option<Self> {
        if (dword >> 16) != 0x0020 {
            return None;
        }
        Some(Self {
            bus: ((dword & 0xffff) >> 8) as u8,
            address: (dword & 0xff) as u8,
        })
    }

    /// Decodes the 4 channel-id bytes, trying both byte orders.
    #[cfg_attr(not(feature = "nfc-backend-pcsc"), allow(dead_code))]
    pub(crate) fn from_channel_id_bytes(bytes: [u8; 4]) -> Option<Self> {
        let dword = u32::from_ne_bytes(bytes);
        Self::from_channel_id(dword).or_else(|| Self::from_channel_id(dword.swap_bytes()))
    }
}

/// Resolves the USB (bus, address) behind a hidraw node via sysfs.
pub(crate) fn usb_id_from_hidraw(path: &std::ffi::CStr) -> Option<UsbDeviceId> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    let name = Path::new(OsStr::from_bytes(path.to_bytes())).file_name()?;
    let mut dir: PathBuf =
        std::fs::canonicalize(Path::new("/sys/class/hidraw").join(name).join("device")).ok()?;

    loop {
        let busnum = dir.join("busnum");
        let devnum = dir.join("devnum");
        if busnum.is_file() && devnum.is_file() {
            return Some(UsbDeviceId {
                bus: read_sysfs_u8(&busnum)?,
                address: read_sysfs_u8(&devnum)?,
            });
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn read_sysfs_u8(path: &std::path::Path) -> Option<u8> {
    // >255 yields None: keep the device rather than risk a false match.
    let value: u32 = std::fs::read_to_string(path).ok()?.trim().parse().ok()?;
    u8::try_from(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_channel_id_decodes_usb() {
        let id = UsbDeviceId::from_channel_id(0x0020_0108).expect("USB marker");
        assert_eq!(id.bus, 1);
        assert_eq!(id.address, 8);
    }

    #[test]
    fn from_channel_id_rejects_non_usb() {
        assert!(UsbDeviceId::from_channel_id(0x0010_0108).is_none());
    }

    #[test]
    fn from_channel_id_bytes_decodes_either_byte_order() {
        let want = UsbDeviceId { bus: 1, address: 8 };
        assert_eq!(
            UsbDeviceId::from_channel_id_bytes([0x08, 0x01, 0x20, 0x00]),
            Some(want)
        );
        assert_eq!(
            UsbDeviceId::from_channel_id_bytes([0x00, 0x20, 0x01, 0x08]),
            Some(want)
        );
    }
}
