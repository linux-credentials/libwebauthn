use super::Context;
use super::channel::{HandlerInCtx, NfcBackend, NfcChannel};
use super::device::NfcDevice;
use crate::webauthn::error::Error;
use crate::transport::error::TransportError;
use apdu::core::HandleError;
use apdu_core;
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

#[derive(Debug)]
pub struct Info {
    connstring: String,
}

impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.connstring)
    }
}

fn map_error(_err: nfc1::Error) -> Error {
    Error::Transport(TransportError::ConnectionFailed)
}

impl From<nfc1::Error> for Error {
    fn from(input: nfc1::Error) -> Self {
        trace!("{:?}", input);
        let output = match input {
            // rs-nfc1 errors
            nfc1::Error::Malloc => TransportError::TransportUnavailable,
            nfc1::Error::Undefined(_c_int) => TransportError::TransportUnavailable,
            nfc1::Error::UndefinedModulationType => TransportError::TransportUnavailable,
            nfc1::Error::NoDeviceFound => TransportError::TransportUnavailable,

            // libnfc errors
            nfc1::Error::Io => TransportError::ConnectionLost,
            nfc1::Error::InvalidArgument => TransportError::NegotiationFailed,
            nfc1::Error::DeviceNotSupported => TransportError::InvalidEndpoint,
            nfc1::Error::NoSuchDeviceFound => TransportError::InvalidEndpoint,
            nfc1::Error::BufferOverflow => TransportError::InvalidFraming,
            nfc1::Error::Timeout => TransportError::Timeout,
            nfc1::Error::OperationAborted => TransportError::InvalidFraming,
            nfc1::Error::NotImplemented => TransportError::NegotiationFailed,
            nfc1::Error::TargetReleased => TransportError::NegotiationFailed,
            nfc1::Error::RfTransmissionError => TransportError::NegotiationFailed,
            nfc1::Error::MifareAuthFailed => TransportError::NegotiationFailed,
            nfc1::Error::Soft => TransportError::Timeout,
            nfc1::Error::Chip => TransportError::InvalidFraming,
        };
        Error::Transport(output)
    }
}

impl Info {
    pub fn new(connstring: &String) -> Self {
        Info {
            connstring: connstring.clone(),
        }
    }

    pub fn channel(&self) -> Result<NfcChannel<Context>, Error> {
        let context = nfc1::Context::new().map_err(|e| map_error(e))?;

        let mut chan = Channel::new(self, context);

        {
            let mut device = chan.device.lock().unwrap();
            device.initiator_init()?;
            device.set_property_bool(nfc1::Property::InfiniteSelect, false)?;

            let info = device.get_information_about()?;
            debug!("Info: {}", info);
        }

        let target = chan.connect_to_target()?;
        debug!("Selected: {:?}", target);

        let ctx = Context {};
        let channel = NfcChannel::new(Box::new(chan), ctx);
        Ok(channel)
    }
}

pub struct Channel {
    device: Arc<Mutex<nfc1::Device>>,
}

unsafe impl Send for Channel {}

impl Channel {
    pub fn new(info: &Info, mut context: nfc1::Context) -> Self {
        let device = context
            .open_with_connstring(&info.connstring)
            .expect("opened device");

        Self {
            device: Arc::new(Mutex::new(device)),
        }
    }

    fn initiator_select_passive_target_ex(
        device: &mut nfc1::Device,
        modulation: &nfc1::Modulation,
    ) -> nfc1::Result<nfc1::Target> {
        match device.initiator_select_passive_target(&modulation) {
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

    fn connect_to_target(&mut self) -> Result<nfc1::Target, Error> {
        let mut device = self.device.lock().unwrap();
        // Assume baudrates are already sorted higher to lower
        let baudrates = device.get_supported_baud_rate(nfc1::Mode::Initiator, MODULATION_TYPE)?;
        let modulations = baudrates
            .iter()
            .map(|baud_rate| nfc1::Modulation {
                modulation_type: MODULATION_TYPE,
                baud_rate: *baud_rate,
            })
            .collect::<Vec<nfc1::Modulation>>();
        let modulation = &modulations[modulations.len() - 1];
        let is_one_rate = modulations.len() == 1;
        for i in 0..2 {
            if i > 0 {
                thread::sleep(Duration::from_millis(100));
            }
            trace!("Poll {:?} {}", modulation, i);
            if let Ok(target) =
                Channel::initiator_select_passive_target_ex(&mut device, &modulation)
            {
                if is_one_rate {
                    return Ok(target);
                }

                for modulation in modulations.iter() {
                    device.initiator_deselect_target()?;
                    device.initiator_init()?;
                    trace!("Try {:?}", modulation);
                    if let Ok(target) =
                        Channel::initiator_select_passive_target_ex(&mut device, &modulation)
                    {
                        return Ok(target);
                    }
                }
            }
        }

        Err(Error::Transport(TransportError::TransportUnavailable))
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
    ) -> apdu_core::Result {
        let timeout = nfc1::Timeout::Duration(TIMEOUT);
        let len = response.len();
        trace!("TX: {:?}", command);
        let rapdu = self
            .device
            .lock()
            .unwrap()
            .initiator_transceive_bytes(command, len, timeout)
            .map_err(|e| HandleError::Nfc(Box::new(e)))?;

        trace!("RX: {:?}", rapdu);

        if response.len() < rapdu.len() {
            return Err(HandleError::NotEnoughBuffer(rapdu.len()));
        }

        response
            .write(&rapdu)
            .map_err(|e| HandleError::Nfc(Box::new(e)))
    }
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::fmt::Result {
        let mut device = self.device.lock().unwrap();
        write!(f, "{}", device.name())
    }
}

impl<Ctx> NfcBackend<Ctx> for Channel where Ctx: fmt::Debug + fmt::Display {}

#[instrument]
pub fn list_devices() -> Result<Vec<NfcDevice>, Error> {
    let mut context =
        nfc1::Context::new().map_err(|_| Error::Transport(TransportError::TransportUnavailable))?;
    let devices = context
        .list_devices(MAX_DEVICES)
        .expect("libnfc devices")
        .iter()
        .map(|x| NfcDevice::new_libnfc(Info::new(x)))
        .collect::<Vec<_>>();

    Ok(devices)
}
