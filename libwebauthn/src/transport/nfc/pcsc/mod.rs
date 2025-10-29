use super::channel::{HandlerInCtx, NfcBackend, NfcChannel};
use super::device::NfcDevice;
use super::Context;
use crate::transport::error::TransportError;
use crate::webauthn::Error;
use apdu::core::HandleError;
use pcsc;
use std::ffi::{CStr, CString};
use std::fmt;
use std::fmt::Debug;
use std::ops::Deref;
use std::sync::{Arc, Mutex};
#[allow(unused_imports)]
use tracing::{debug, info, instrument, trace};

#[derive(Clone, Debug)]
pub struct Info {
    name: CString,
}

pub struct PcscCard {
    pub card: Option<pcsc::Card>,
}

impl<'tx> Deref for PcscCard {
    type Target = pcsc::Card;

    fn deref(&self) -> &pcsc::Card {
        self.card.as_ref().unwrap()
    }
}

// By default pcsc resets the card but to be able to reconnect the
// card has to be powered down instead.
impl Drop for PcscCard {
    fn drop(&mut self) {
        let _ = PcscCard::disconnect(self.card.take());
    }
}

impl PcscCard {
    pub fn new(card: pcsc::Card) -> Self {
        PcscCard { card: Some(card) }
    }

    fn map_disconnect_error(pair: (pcsc::Card, pcsc::Error)) -> Error {
        let (_card, _err) = pair;
        Error::Transport(TransportError::InvalidFraming)
    }

    fn disconnect(card: Option<pcsc::Card>) -> Result<(), Error> {
        match card {
            Some(card) => {
                debug!("Disconnect card");
                card.disconnect(pcsc::Disposition::UnpowerCard)
                    .map_err(PcscCard::map_disconnect_error)
            }
            None => Ok(()),
        }
    }
}

pub struct Channel {
    card: Arc<Mutex<PcscCard>>,
}

unsafe impl Send for Channel {}

impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.name)
    }
}

impl From<pcsc::Error> for Error {
    fn from(input: pcsc::Error) -> Self {
        trace!("{:?}", input);
        let output = match input {
            pcsc::Error::NoSmartcard => TransportError::ConnectionFailed,
            _ => TransportError::InvalidFraming,
        };

        Error::Transport(output)
    }
}

impl Info {
    pub fn new(name: &CStr) -> Self {
        Info {
            name: CStr::into_c_string(name.into()),
        }
    }

    pub fn channel(&self) -> Result<NfcChannel<Context>, Error> {
        let context = pcsc::Context::establish(pcsc::Scope::User)?;
        let chan = Channel::new(self, context)?;

        let ctx = Context {};
        let channel = NfcChannel::new(Box::new(chan), ctx);
        Ok(channel)
    }
}

impl Channel {
    pub fn new(info: &Info, context: pcsc::Context) -> Result<Self, Error> {
        let card = context.connect(&info.name, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)?;

        let chan = Self {
            card: Arc::new(Mutex::new(PcscCard::new(card))),
        };

        Ok(chan)
    }
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::fmt::Result {
        let card = self.card.lock().unwrap();
        let (names_len, atr_len) = card.status2_len().unwrap();
        let mut names_buf = vec![0; names_len];
        let mut atr_buf = vec![0; atr_len];
        let status = card.status2(&mut names_buf, &mut atr_buf).unwrap();
        write!(f, "{:?}", status.reader_names().collect::<Vec<_>>())
    }
}

impl<Ctx> NfcBackend<Ctx> for Channel where Ctx: fmt::Debug + fmt::Display {}

impl<Ctx> HandlerInCtx<Ctx> for Channel
where
    Ctx: fmt::Debug + fmt::Display,
{
    fn handle_in_ctx(
        &mut self,
        _ctx: Ctx,
        command: &[u8],
        response: &mut [u8],
    ) -> apdu_core::Result {
        trace!("TX: {:?}", command);

        let rapdu = self
            .card
            .lock()
            .unwrap()
            .transmit(command, response)
            .map_err(|e| HandleError::Nfc(Box::new(e)))?;

        trace!("RX: {:?}", rapdu);
        Ok(rapdu.len())
    }
}

#[instrument]
pub(crate) fn is_nfc_available() -> bool {
    let Ok(ctx) = pcsc::Context::establish(pcsc::Scope::User) else {
        return false;
    };
    // If there is no reader, we say NFC is not available
    ctx.list_readers_len().unwrap_or_default() > 0
}

#[instrument]
pub(crate) fn list_devices() -> Result<Vec<NfcDevice>, Error> {
    let ctx = pcsc::Context::establish(pcsc::Scope::User).expect("PC/SC context");
    let len = ctx.list_readers_len().expect("PC/SC readers len");
    if len == 0 {
        return Err(Error::Transport(TransportError::TransportUnavailable));
    }
    let mut readers_buf = vec![0; len];
    let devices = ctx
        .list_readers(&mut readers_buf)
        .expect("PC/SC readers")
        .map(|x| NfcDevice::new_pcsc(Info::new(x)))
        .collect::<Vec<NfcDevice>>();

    Ok(devices)
}
