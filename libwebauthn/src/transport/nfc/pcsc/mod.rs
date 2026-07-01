use super::channel::{HandlerInCtx, NfcBackend, NfcChannel};
use super::device::NfcDevice;
use super::error::NfcError;
use super::Context;
use crate::transport::usb::UsbDeviceId;
use crate::transport::ChannelSettings;
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
    display_name: String,
}

pub struct PcscCard {
    card: Option<pcsc::Card>,
}

impl Deref for PcscCard {
    type Target = pcsc::Card;

    #[allow(clippy::unwrap_used)] // The Option is always Some; it is only taken in Drop.
    fn deref(&self) -> &pcsc::Card {
        self.card.as_ref().unwrap()
    }
}

// By default pcsc resets the card but to be able to reconnect the
// card has to be powered down instead.
impl Drop for PcscCard {
    fn drop(&mut self) {
        if let Some(card) = self.card.take() {
            debug!("Disconnect card");
            let _ = card.disconnect(pcsc::Disposition::UnpowerCard);
        }
    }
}

impl PcscCard {
    pub fn new(card: pcsc::Card) -> Self {
        PcscCard { card: Some(card) }
    }
}

pub struct Channel {
    name: String,
    card: Arc<Mutex<PcscCard>>,
}

unsafe impl Send for Channel {}

impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name)
    }
}

impl Info {
    pub fn new(name: &CStr) -> Self {
        let cstring = name.to_owned();
        let display_name = cstring.to_string_lossy().into_owned();
        Info {
            name: cstring,
            display_name,
        }
    }

    pub fn channel(&self, settings: ChannelSettings) -> Result<NfcChannel<Context>, NfcError> {
        let context = pcsc::Context::establish(pcsc::Scope::User)?;
        let chan = Channel::new(self, context)?;

        let ctx = Context {};
        let channel = NfcChannel::new(Box::new(chan), ctx, settings);
        Ok(channel)
    }

    pub(crate) fn usb_device_id(&self) -> Option<UsbDeviceId> {
        usb_id_from_reader(&self.name)
    }
}

/// Reads the reader's `SCARD_ATTR_CHANNEL_ID` to get its USB (bus, address).
/// Connects in `Direct` mode so no card is required and none is reset.
pub(crate) fn usb_id_from_reader(name: &CStr) -> Option<UsbDeviceId> {
    let context = pcsc::Context::establish(pcsc::Scope::User).ok()?;
    let card = context
        .connect(name, pcsc::ShareMode::Direct, pcsc::Protocols::UNDEFINED)
        .ok()?;

    let mut buf = [0u8; 8];
    let id = card
        .get_attribute(pcsc::Attribute::ChannelId, &mut buf)
        .ok()
        .and_then(|attr| attr.get(..4)?.try_into().ok())
        .and_then(UsbDeviceId::from_channel_id_bytes);

    // If disconnect fails, forget the returned Card so its Drop cannot reset an
    // inserted card. The context release below frees the handle.
    if let Err((card, _)) = card.disconnect(pcsc::Disposition::LeaveCard) {
        std::mem::forget(card);
    }
    id
}

impl Channel {
    pub fn new(info: &Info, context: pcsc::Context) -> Result<Self, NfcError> {
        let card = context.connect(&info.name, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)?;

        let chan = Self {
            name: info.display_name.clone(),
            card: Arc::new(Mutex::new(PcscCard::new(card))),
        };

        Ok(chan)
    }
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
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
    ) -> Result<usize, NfcError> {
        trace!("TX: {:?}", command);

        let card = self.card.lock().map_err(|_| NfcError::MutexPoisoned)?;
        let rapdu = card.transmit(command, response).map_err(NfcError::Pcsc)?;

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
pub(crate) fn list_devices() -> Result<Vec<NfcDevice>, NfcError> {
    let ctx = pcsc::Context::establish(pcsc::Scope::User)?;
    let len = ctx.list_readers_len()?;
    if len == 0 {
        return Err(NfcError::NoReader);
    }
    let mut readers_buf = vec![0; len];
    let devices = ctx
        .list_readers(&mut readers_buf)?
        .map(|x| NfcDevice::new_pcsc(Info::new(x)))
        .collect::<Vec<NfcDevice>>();

    Ok(devices)
}
