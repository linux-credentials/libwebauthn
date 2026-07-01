use super::channel::{HandlerInCtx, NfcBackend, NfcChannel};
use super::device::NfcDevice;
use super::error::NfcError;
use super::Context;
use crate::transport::ChannelSettings;
use std::fmt;
use std::fmt::Debug;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
#[allow(unused_imports)]
use tracing::{debug, info, instrument, trace};

const MAX_DEVICES: usize = 10;
const TIMEOUT: Duration = Duration::from_millis(5000);
const MODULATION_TYPE: nfc1::ModulationType = nfc1::ModulationType::Iso14443a;

#[derive(Clone, Debug)]
pub struct Info {
    connstring: String,
}

impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.connstring)
    }
}

impl Info {
    pub fn new(connstring: &str) -> Self {
        Info {
            connstring: connstring.to_string(),
        }
    }

    pub fn channel(&self, settings: ChannelSettings) -> Result<NfcChannel<Context>, NfcError> {
        let context = nfc1::Context::new()?;

        let mut chan = Channel::new(self, context)?;

        {
            let mut device = chan.device.lock().map_err(|_| NfcError::MutexPoisoned)?;
            device.initiator_init()?;
            device.set_property_bool(nfc1::Property::InfiniteSelect, false)?;

            let info = device.get_information_about()?;
            debug!("Info: {}", info);
        }

        let target = chan.connect_to_target()?;
        debug!("Selected: {:?}", target);

        let ctx = Context {};
        let channel = NfcChannel::new(Box::new(chan), ctx, settings);
        Ok(channel)
    }
}

pub struct Channel {
    name: String,
    device: Arc<Mutex<nfc1::Device>>,
}

unsafe impl Send for Channel {}

impl Channel {
    pub fn new(info: &Info, mut context: nfc1::Context) -> Result<Self, NfcError> {
        let mut device = context.open_with_connstring(&info.connstring)?;
        let name = device.name().to_owned();

        Ok(Self {
            name,
            device: Arc::new(Mutex::new(device)),
        })
    }

    fn initiator_select_passive_target_ex(
        device: &mut nfc1::Device,
        modulation: &nfc1::Modulation,
    ) -> nfc1::Result<nfc1::Target> {
        match device.initiator_select_passive_target(modulation) {
            Ok(target) => {
                if let nfc1::target_info::TargetInfo::Iso14443a(iso) = target.target_info {
                    if iso.uid_len > 0 {
                        Ok(target)
                    } else {
                        Err(nfc1::Error::NoDeviceFound)
                    }
                } else {
                    Err(nfc1::Error::NoDeviceFound)
                }
            }
            Err(err) => {
                println!("Error: {}", err);
                Err(err)
            }
        }
    }

    fn connect_to_target(&mut self) -> Result<nfc1::Target, NfcError> {
        let mut device = self.device.lock().map_err(|_| NfcError::MutexPoisoned)?;
        // Assume baudrates are already sorted higher to lower
        let baudrates = device.get_supported_baud_rate(nfc1::Mode::Initiator, MODULATION_TYPE)?;
        let modulations = baudrates
            .iter()
            .map(|baud_rate| nfc1::Modulation {
                modulation_type: MODULATION_TYPE,
                baud_rate: *baud_rate,
            })
            .collect::<Vec<nfc1::Modulation>>();
        let modulation = modulations.last().ok_or(NfcError::NoTarget)?;
        let is_one_rate = modulations.len() == 1;
        for i in 0..2 {
            if i > 0 {
                thread::sleep(Duration::from_millis(100));
            }
            trace!("Poll {:?} {}", modulation, i);
            if let Ok(target) = Channel::initiator_select_passive_target_ex(&mut device, modulation)
            {
                if is_one_rate {
                    return Ok(target);
                }

                for modulation in modulations.iter() {
                    device.initiator_deselect_target()?;
                    device.initiator_init()?;
                    trace!("Try {:?}", modulation);
                    if let Ok(target) =
                        Channel::initiator_select_passive_target_ex(&mut device, modulation)
                    {
                        return Ok(target);
                    }
                }
            }
        }

        Err(NfcError::NoTarget)
    }
}

impl<Ctx> HandlerInCtx<Ctx> for Channel
where
    Ctx: fmt::Debug + fmt::Display,
{
    fn handle_in_ctx(
        &mut self,
        _ctx: Ctx,
        command: &[u8],
        mut response: &mut [u8],
    ) -> Result<usize, NfcError> {
        let timeout = nfc1::Timeout::Duration(TIMEOUT);
        let len = response.len();
        trace!("TX: {:?}", command);
        let rapdu = self
            .device
            .lock()
            .map_err(|_| NfcError::MutexPoisoned)?
            .initiator_transceive_bytes(command, len, timeout)
            .map_err(NfcError::LibNfc)?;

        trace!("RX: {:?}", rapdu);

        if response.len() < rapdu.len() {
            return Err(NfcError::BufferOverflow(rapdu.len()));
        }

        response.write(&rapdu).map_err(NfcError::Io)
    }
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl<Ctx> NfcBackend<Ctx> for Channel where Ctx: fmt::Debug + fmt::Display {}

#[instrument]
pub(crate) fn is_nfc_available() -> bool {
    let Ok(mut context) = nfc1::Context::new() else {
        return false;
    };
    // "list_devices()" lists readers. If none is found, we say it is not available
    context.list_devices(1).map(|d| d.len()).unwrap_or_default() > 0
}

#[instrument]
pub(crate) fn list_devices() -> Result<Vec<NfcDevice>, NfcError> {
    let mut context = nfc1::Context::new()?;
    let devices = context
        .list_devices(MAX_DEVICES)?
        .iter()
        .map(|x| NfcDevice::new_libnfc(Info::new(x)))
        .collect::<Vec<_>>();

    Ok(devices)
}
