use std::convert::TryFrom;
use std::fmt::{Debug, Display, Formatter};
use std::io::{Cursor as IOCursor, Seek, SeekFrom};
use std::ops::DerefMut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use byteorder::{BigEndian, ReadBytesExt};
use hidapi::HidDevice as HidApiDevice;
use rand::{thread_rng, Rng};
use tokio::sync::{broadcast, Notify};
use tokio::time::sleep;
use tracing::{debug, info, instrument, trace, warn, Level};

use crate::proto::ctap1::apdu::{ApduRequest, ApduResponse};
use crate::proto::ctap1::{Ctap1, Ctap1RegisterRequest};
use crate::proto::ctap2::cbor::{CborRequest, CborResponse};
#[cfg(test)]
use crate::proto::ctap2::Ctap2PinUvAuthProtocol;
use crate::proto::ctap2::{Ctap2, Ctap2MakeCredentialRequest};
use crate::proto::CtapError;
use crate::transport::channel::{AuthTokenData, Channel, ChannelStatus, Ctap2AuthTokenStore};
use crate::transport::device::SupportedProtocols;
use crate::transport::error::TransportError;
use crate::transport::hid::framing::{
    HidCommand, HidMessage, HidMessageParser, HidMessageParserState,
};
#[cfg(test)]
use crate::transport::virt;
use crate::webauthn::error::{Error, PlatformError};
use crate::UvUpdate;

use super::device::get_hidapi;
use super::device::HidBackendDevice;
use super::HidDevice;

const INIT_NONCE_LEN: usize = 8;
const INIT_PAYLOAD_LEN: usize = 17;
const INIT_TIMEOUT: Duration = Duration::from_millis(200);

const PACKET_SIZE: usize = 64;
const REPORT_ID: u8 = 0x00;

// Per-iteration cap on hidapi::read_timeout. `read_timeout` returns as soon
// as the device delivers a report, so this does NOT add latency to normal
// responses; it only bounds how quickly the loop wakes up to re-check the
// wall-clock deadline and the cancel flag. 100ms is a small fraction of any
// realistic CTAP timeout, gives ~10 wakeups/sec per active channel (cheap
// even on battery), and is short enough that user-perceived cancel latency
// stays well under the round-trip a click already costs.
const HID_READ_POLL_INTERVAL: Duration = Duration::from_millis(100);

// Some devices fail when sending a WINK command followed immediately
// by a CBOR command, so we want to ensure we wait some time after winking.
const WINK_MIN_WAIT: Duration = Duration::from_secs(2);

enum OpenHidDevice {
    HidApiDevice(Arc<Mutex<HidApiDevice>>),
    #[cfg(test)]
    VirtualDevice(Arc<Mutex<virt::VirtHidDevice>>),
}

/// Shared cancel state. The atomic flag is checked by the blocking hidapi
/// reader between poll iterations; the notify wakes the async caller so a
/// cancel observed from another task is seen without waiting out the poll
/// interval.
#[derive(Debug, Default)]
struct CancelState {
    flag: AtomicBool,
    notify: Notify,
}

impl CancelState {
    fn signal(&self) {
        self.flag.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    fn reset(&self) {
        self.flag.store(false, Ordering::SeqCst);
    }
}

#[derive(Debug, Clone)]
pub struct HidChannelHandle {
    cancel: Arc<CancelState>,
}

impl HidChannelHandle {
    pub async fn cancel_ongoing_operation(&self) {
        self.cancel.signal();
    }
}

pub struct HidChannel<'d> {
    status: ChannelStatus,
    device: &'d HidDevice,
    open_device: OpenHidDevice,
    init: InitResponse,
    auth_token_data: Option<AuthTokenData>,
    ux_update_sender: broadcast::Sender<UvUpdate>,
    handle: HidChannelHandle,
    cancel: Arc<CancelState>,
    #[cfg(test)]
    pin_protocol_override: Option<Ctap2PinUvAuthProtocol>,
}

impl<'d> HidChannel<'d> {
    pub async fn new(device: &'d HidDevice) -> Result<HidChannel<'d>, Error> {
        let (ux_update_sender, _) = broadcast::channel(16);
        let cancel = Arc::new(CancelState::default());
        let handle = HidChannelHandle {
            cancel: cancel.clone(),
        };

        let mut channel = Self {
            status: ChannelStatus::Ready,
            device,
            open_device: match device.backend {
                HidBackendDevice::HidApiDevice(_) => {
                    let hidapi_device = Self::hid_open(device)?;
                    OpenHidDevice::HidApiDevice(Arc::new(Mutex::new(hidapi_device)))
                }
                #[cfg(test)]
                HidBackendDevice::VirtualDevice => {
                    OpenHidDevice::VirtualDevice(Arc::new(Mutex::new(virt::VirtHidDevice::new())))
                }
            },
            init: InitResponse::default(),
            auth_token_data: None,
            ux_update_sender,
            handle,
            cancel,
            #[cfg(test)]
            pin_protocol_override: None,
        };
        channel.init = channel.init(INIT_TIMEOUT).await?;
        Ok(channel)
    }

    pub fn get_handle(&self) -> HidChannelHandle {
        self.handle.clone()
    }

    #[instrument(skip_all)]
    pub async fn wink(&mut self, timeout: Duration) -> Result<bool, Error> {
        if !self.init.caps.contains(Caps::WINK) {
            warn!(?self.init.caps, "WINK capability is not supported");
            return Ok(false);
        }

        self.hid_send(&HidMessage::new(self.init.cid, HidCommand::Wink, &[]))
            .await?;
        // Solokey does not seem to return an answer for wink and hangs here.
        let _ = self.hid_recv(timeout).await?;

        sleep(WINK_MIN_WAIT).await;
        Ok(true)
    }

    #[instrument(skip_all)]
    pub async fn blink_and_wait_for_user_presence(
        &mut self,
        timeout: Duration,
    ) -> Result<bool, Error> {
        let supported = self.supported_protocols().await?;
        if supported.fido2 {
            let get_info_response = self.ctap2_get_info().await?;
            if get_info_response.supports_fido_2_1() {
                match self.ctap2_selection(timeout).await {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            } else {
                info!("Creating dummy request to make the device blink");
                let ctap2_request = Ctap2MakeCredentialRequest::dummy();
                match self.ctap2_make_credential(&ctap2_request, timeout).await {
                    Ok(_)
                    | Err(Error::Ctap(CtapError::PINInvalid))
                    | Err(Error::Ctap(CtapError::PINAuthInvalid))
                    | Err(Error::Ctap(CtapError::PINNotSet)) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
        } else if supported.u2f {
            info!("Creating dummy request to make the device blink");
            let register_request = Ctap1RegisterRequest::dummy(timeout);
            match self.ctap1_register(&register_request).await {
                Ok(_)
                | Err(Error::Ctap(CtapError::PINInvalid))
                | Err(Error::Ctap(CtapError::PINAuthInvalid))
                | Err(Error::Ctap(CtapError::PINNotSet)) => Ok(true),
                Err(_) => Ok(false),
            }
        } else {
            // Neither fido2 nor u2f supported, so we just mark it as not selected
            Ok(false)
        }
    }

    #[instrument(level = Level::DEBUG, skip_all)]
    async fn init(&mut self, timeout: Duration) -> Result<InitResponse, Error> {
        let nonce: [u8; 8] = thread_rng().gen();
        let request = HidMessage::broadcast(HidCommand::Init, &nonce);

        self.hid_send(&request).await?;
        let response = self.hid_recv(timeout).await?;

        if response.cmd != HidCommand::Init {
            warn!(?response.cmd, "Invalid response to INIT request");
            return Err(Error::Transport(TransportError::InvalidEndpoint));
        }

        if response.payload.len() < INIT_PAYLOAD_LEN {
            warn!(
                { len = response.payload.len() },
                "INIT payload is too small"
            );
            return Err(Error::Transport(TransportError::InvalidEndpoint));
        }

        if response.payload[0..INIT_NONCE_LEN] != nonce[0..INIT_NONCE_LEN] {
            warn!("INIT nonce mismatch. Terminating.");
            return Err(Error::Transport(TransportError::InvalidEndpoint));
        }

        let mut cursor = IOCursor::new(response.payload);
        cursor
            .seek(SeekFrom::Start(8))
            .map_err(|e| Error::Transport(TransportError::IoError(e.kind())))?;

        let init = InitResponse {
            cid: cursor
                .read_u32::<BigEndian>()
                .map_err(|e| Error::Transport(TransportError::IoError(e.kind())))?,
            protocol_version: cursor
                .read_u8()
                .map_err(|e| Error::Transport(TransportError::IoError(e.kind())))?,
            version_major: cursor
                .read_u8()
                .map_err(|e| Error::Transport(TransportError::IoError(e.kind())))?,
            version_minor: cursor
                .read_u8()
                .map_err(|e| Error::Transport(TransportError::IoError(e.kind())))?,
            version_build: cursor
                .read_u8()
                .map_err(|e| Error::Transport(TransportError::IoError(e.kind())))?,
            caps: Caps::from_bits_truncate(
                cursor
                    .read_u8()
                    .map_err(|e| Error::Transport(TransportError::IoError(e.kind())))?,
            ),
        };

        debug!(?init, "Device init complete");
        Ok(init)
    }

    fn hid_open(device: &HidDevice) -> Result<HidApiDevice, Error> {
        let hidapi = get_hidapi()?;
        match &device.backend {
            HidBackendDevice::HidApiDevice(device) => Ok(device
                .open_device(&hidapi)
                .or(Err(Error::Transport(TransportError::ConnectionFailed)))?),
            #[cfg(test)]
            HidBackendDevice::VirtualDevice => unreachable!(),
        }
    }

    #[instrument(level = Level::DEBUG, skip_all)]
    pub async fn hid_cancel(&self) -> Result<(), Error> {
        self.hid_send(&HidMessage::new(self.init.cid, HidCommand::Cancel, &[]))
            .await
    }

    /*
    #[instrument(level = Level::DEBUG, skip_all)]
    async fn hid_transact(
        device: &'d HidDevice,
        msg: &HidMessage,
        timeout: Duration,
    ) -> Result<HidMessage, Error> {
        match device.backend {
            HidBackendDevice::HidApiDevice(_) => {
                Self::hid_transact_hidapi(device, msg, timeout).await
            }
            #[cfg(feature = "virtual-hid-device")]
            HidBackendDevice::VirtualDevice(_) => {
                Self::hid_transact_virtual(device, msg, timeout).await
            }
        }
    }
    */

    /*
    async fn hid_transact_hidapi(
        device: &'d HidDevice,
        msg: &HidMessage,
        timeout: Duration,
    ) -> Result<HidMessage, Error> {
        Self::hid_cancel(device, msg.cid, &hidapi_device)?;
        Self::hid_send(device, msg, &hidapi_device)?;

        let response = loop {
            let response = Self::hid_receive(device, &hidapi_device, timeout)?;
            match response.cmd {
                HidCommand::KeepAlive => {
                    debug!("Ignoring HID keep-alive");
                    continue;
                }
                _ => break response,
            }
        };
        Ok(response)
    }
    */

    #[instrument(skip_all, fields(cmd = ?msg.cmd, payload_len = msg.payload.len()))]
    pub async fn hid_send(&self, msg: &HidMessage) -> Result<(), Error> {
        match &self.open_device {
            OpenHidDevice::HidApiDevice(hidapi_device) => {
                let Ok(mut guard) = hidapi_device.lock() else {
                    warn!("Poisoned lock on HID API device");
                    return Err(Error::Transport(TransportError::ConnectionLost));
                };
                let device = guard.deref_mut();
                let response = Self::hid_send_hidapi(device, &self.cancel, msg);
                if matches!(response, Err(Error::Platform(PlatformError::Cancelled))) {
                    // CTAPHID_CANCEL must still reach the device even though
                    // the cancel flag is set; bypass the flag check via
                    // write_packets (also avoids recursing into hid_cancel).
                    let cancel_msg = HidMessage::new(self.init.cid, HidCommand::Cancel, &[]);
                    let _ = Self::write_packets(device, &cancel_msg);
                }
                response
            }
            #[cfg(test)]
            OpenHidDevice::VirtualDevice(virt_device) => {
                let Ok(mut guard) = virt_device.lock() else {
                    panic!("Poisoned lock on Virtual HID device");
                };
                let device = guard.deref_mut();
                device.virt_send(msg)
            }
        }
    }

    fn hid_send_hidapi(
        device: &hidapi::HidDevice,
        cancel: &CancelState,
        msg: &HidMessage,
    ) -> Result<(), Error> {
        let packets = msg
            .packets(PACKET_SIZE)
            .or(Err(Error::Transport(TransportError::InvalidFraming)))?;
        for (i, packet) in packets.iter().enumerate() {
            if cancel.is_cancelled() {
                return Err(Error::Platform(PlatformError::Cancelled));
            }

            let mut report: Vec<u8> = vec![REPORT_ID];
            report.extend(packet);
            report.extend(vec![0; PACKET_SIZE - packet.len()]);
            debug!({ packet = i, len = report.len() }, "Sending packet as HID report",);
            trace!(?report);
            device
                .write(&report)
                .or(Err(Error::Transport(TransportError::ConnectionLost)))?;
        }
        Ok(())
    }

    /// Send a message without consulting the cancel flag. Used when emitting
    /// CTAPHID_CANCEL after a cancellation has already been observed.
    fn write_packets(device: &hidapi::HidDevice, msg: &HidMessage) -> Result<(), Error> {
        let packets = msg
            .packets(PACKET_SIZE)
            .or(Err(Error::Transport(TransportError::InvalidFraming)))?;
        for packet in &packets {
            let mut report: Vec<u8> = vec![REPORT_ID];
            report.extend(packet);
            report.extend(vec![0; PACKET_SIZE - packet.len()]);
            device
                .write(&report)
                .or(Err(Error::Transport(TransportError::ConnectionLost)))?;
        }
        Ok(())
    }

    #[instrument(skip_all)]
    pub async fn hid_recv(&self, timeout: Duration) -> Result<HidMessage, Error> {
        // Reset the cancel flag so a prior cancellation does not short-circuit
        // a fresh receive. The drop guard signals the flag if this future is
        // dropped before completing, so the blocking reader self-terminates
        // within one HID_READ_POLL_INTERVAL.
        self.cancel.reset();
        let mut drop_guard = CancelOnDrop::new(&self.cancel);

        let result = self.hid_recv_inner(timeout).await;
        drop_guard.disarm();
        result
    }

    async fn hid_recv_inner(&self, timeout: Duration) -> Result<HidMessage, Error> {
        loop {
            let response = match &self.open_device {
                OpenHidDevice::HidApiDevice(hidapi_device) => {
                    let device = Arc::clone(hidapi_device);
                    let cancel = Arc::clone(&self.cancel);
                    // The HID device will block when waiting for a user to
                    // interact with the device, so mark the task as blocking to
                    // allow other tasks to complete.
                    // Note that we're just using spawn_blocking() on hid_recv(), not on hid_send(),
                    // since implementing this on hid_send and would cause unnecessary copies/locking.
                    let read = tokio::task::spawn_blocking(move || {
                        let Ok(mut guard) = device.lock() else {
                            warn!("Poisoned lock on HID API device");
                            return Err(Error::Transport(TransportError::ConnectionLost));
                        };
                        let device = guard.deref_mut();
                        Self::hid_recv_hidapi(device, &cancel, timeout)
                    });
                    tokio::pin!(read);
                    // Race the blocking read against cancel notifications.
                    // spawn_blocking cannot be aborted, so the flag store
                    // here is observed by the reader on its next poll
                    // (bounded by HID_READ_POLL_INTERVAL).
                    loop {
                        tokio::select! {
                            res = &mut read => {
                                break res.map_err(|e| {
                                    warn!(?e, "HID read task failed");
                                    Error::Transport(TransportError::ConnectionLost)
                                })?;
                            }
                            _ = self.cancel.notify.notified() => {
                                self.cancel.flag.store(true, Ordering::SeqCst);
                            }
                        }
                    }
                }
                #[cfg(test)]
                OpenHidDevice::VirtualDevice(virt_device) => {
                    let Ok(mut guard) = virt_device.lock() else {
                        panic!("Poisoned lock on Virtual HID device");
                    };
                    let device = guard.deref_mut();
                    device.virt_recv()
                }
            };

            match response {
                Ok(HidMessage {
                    cmd: HidCommand::KeepAlive,
                    ..
                }) => {
                    debug!("Ignoring HID keep-alive");
                    continue;
                }
                Err(Error::Platform(PlatformError::Cancelled))
                | Err(Error::Transport(TransportError::Timeout)) => {
                    // CTAP 2.2 §11.2.9.1.5: send CTAPHID_CANCEL when the
                    // platform gives up (caller cancelled or wall-clock
                    // budget exhausted). The blocking reader has released
                    // the device mutex by now; reset the flag so the send
                    // itself is not short-circuited.
                    self.cancel.reset();
                    let _ = self.hid_cancel().await;
                    break response;
                }
                _ => break response,
            }
        }
    }

    fn hid_recv_hidapi(
        device: &hidapi::HidDevice,
        cancel: &CancelState,
        timeout: Duration,
    ) -> Result<HidMessage, Error> {
        let mut parser = HidMessageParser::new();
        let deadline = Instant::now().checked_add(timeout);
        loop {
            if cancel.is_cancelled() {
                return Err(Error::Platform(PlatformError::Cancelled));
            }

            // Cap each read at HID_READ_POLL_INTERVAL so we re-check the
            // cancel flag and remaining budget; a stalled device cannot
            // hang the caller past `timeout`.
            let remaining = match deadline {
                Some(d) => d.saturating_duration_since(Instant::now()),
                None => timeout,
            };
            if remaining.is_zero() {
                warn!("HID receive timed out before any data was read");
                return Err(Error::Transport(TransportError::Timeout));
            }
            let read_for = remaining.min(HID_READ_POLL_INTERVAL);

            let mut report = [0; PACKET_SIZE];
            let bytes_read = device
                .read_timeout(&mut report, read_for.as_millis() as i32)
                .or(Err(Error::Transport(TransportError::ConnectionLost)))?;
            if bytes_read == 0 {
                // hidapi signals per-iteration timeout as Ok(0); retry
                // against the remaining budget rather than passing the
                // zero-initialised buffer to the parser.
                trace!("hidapi read_timeout returned 0 bytes, continuing");
                continue;
            }
            debug!({ len = bytes_read }, "Received HID report");
            trace!(?report);
            if let HidMessageParserState::Done = parser
                .update(&report)
                .or(Err(Error::Transport(TransportError::InvalidFraming)))?
            {
                break;
            }
        }

        let response = parser
            .message()
            .or(Err(Error::Transport(TransportError::InvalidFraming)))?;
        debug!({ cmd = ?response.cmd, payload_len = response.payload.len() }, "Received U2F HID response");
        trace!(?response);
        Ok(response)
    }
}

/// Signals the cancel flag if its scope exits via panic or future-drop.
/// Call `disarm()` on the normal-return path.
struct CancelOnDrop<'a> {
    cancel: &'a CancelState,
    armed: bool,
}

impl<'a> CancelOnDrop<'a> {
    fn new(cancel: &'a CancelState) -> Self {
        Self {
            cancel,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CancelOnDrop<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.cancel.signal();
        }
    }
}

impl Drop for HidChannel<'_> {
    #[instrument(level = Level::DEBUG, skip_all, fields(dev = %self.device))]
    fn drop(&mut self) {
        #[cfg(test)]
        if matches!(self.device.backend, HidBackendDevice::VirtualDevice) {
            return;
        }

        // Lock-free: signal any in-flight blocking read to abort on its
        // next poll iteration. Then best-effort emit CTAPHID_CANCEL via
        // try_lock; if the device mutex is contended (reader still active)
        // we skip — the reader is about to release it and the device's
        // own transaction timeout will reclaim the channel.
        self.cancel.signal();

        match &self.open_device {
            OpenHidDevice::HidApiDevice(hidapi_device) => match hidapi_device.try_lock() {
                Ok(mut guard) => {
                    let device = guard.deref_mut();
                    let cancel_msg = HidMessage::new(self.init.cid, HidCommand::Cancel, &[]);
                    if let Err(err) = Self::write_packets(device, &cancel_msg) {
                        debug!(?err, "Best-effort CTAPHID_CANCEL on channel drop failed");
                    }
                }
                Err(_) => {
                    debug!("Device mutex contended on drop, skipping CTAPHID_CANCEL packet");
                }
            },
            #[cfg(test)]
            OpenHidDevice::VirtualDevice(_) => {}
        }
    }
}

impl Display for HidChannel<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.device, f)
    }
}

#[async_trait]
impl Channel for HidChannel<'_> {
    type UxUpdate = UvUpdate;

    async fn supported_protocols(&self) -> Result<SupportedProtocols, Error> {
        let cbor_supported = self.init.caps.contains(Caps::CBOR);
        let apdu_supported = !self.init.caps.contains(Caps::NO_MSG);
        Ok(SupportedProtocols {
            u2f: apdu_supported,
            fido2: cbor_supported,
        })
    }

    async fn status(&self) -> ChannelStatus {
        self.status
    }

    async fn close(&mut self) {}

    async fn apdu_send(
        &mut self,
        request: &ApduRequest,
        _timeout: std::time::Duration,
    ) -> Result<(), Error> {
        let cid = self.init.cid;
        debug!({ cid }, "Sending APDU request");
        trace!(?request);
        let apdu_raw = request
            .raw_long()
            .map_err(|e| TransportError::IoError(e.kind()))?;
        self.hid_send(&HidMessage::new(cid, HidCommand::Msg, &apdu_raw))
            .await?;
        Ok(())
    }

    async fn apdu_recv(&mut self, timeout: std::time::Duration) -> Result<ApduResponse, Error> {
        let hid_response = self.hid_recv(timeout).await?;
        let apdu_response = ApduResponse::try_from(&hid_response.payload)
            .or(Err(Error::Transport(TransportError::InvalidFraming)))?;
        debug!("Received APDU response");
        trace!(?apdu_response);
        Ok(apdu_response)
    }

    async fn cbor_send(&mut self, request: &CborRequest, _timeout: Duration) -> Result<(), Error> {
        let cid = self.init.cid;
        debug!({ cid }, "Sending CBOR request");
        trace!(?request);
        self.hid_send(&HidMessage::new(
            cid,
            HidCommand::Cbor,
            &request.ctap_hid_data(),
        ))
        .await?;
        Ok(())
    }

    async fn cbor_recv(&mut self, timeout: Duration) -> Result<CborResponse, Error> {
        let hid_response = self.hid_recv(timeout).await?;
        let cbor_response = CborResponse::try_from(&hid_response.payload)
            .or(Err(Error::Transport(TransportError::InvalidFraming)))?;
        debug!(
            { status = ?cbor_response.status_code },
            "Received CBOR response"
        );
        trace!(?cbor_response);
        Ok(cbor_response)
    }

    fn get_ux_update_sender(&self) -> &broadcast::Sender<UvUpdate> {
        &self.ux_update_sender
    }

    #[cfg(test)]
    fn set_forced_pin_protocol(&mut self, protocols: Ctap2PinUvAuthProtocol) {
        self.pin_protocol_override = Some(protocols);
    }

    #[cfg(test)]
    fn get_forced_pin_protocol(&mut self) -> Option<Ctap2PinUvAuthProtocol> {
        self.pin_protocol_override
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct InitResponse {
    pub cid: u32,
    pub protocol_version: u8,
    pub version_major: u8,
    pub version_minor: u8,
    pub version_build: u8,
    pub caps: Caps,
}

bitflags! {
    #[derive(Default, Copy, Clone, Debug)]
    pub struct Caps: u8 {
        const WINK = 0x01;
        const CBOR = 0x04;
        const NO_MSG = 0x08;
    }
}

impl Ctap2AuthTokenStore for HidChannel<'_> {
    fn store_auth_data(&mut self, auth_token_data: AuthTokenData) {
        self.auth_token_data = Some(auth_token_data);
    }

    fn get_auth_data(&self) -> Option<&AuthTokenData> {
        self.auth_token_data.as_ref()
    }

    fn clear_uv_auth_token_store(&mut self) {
        self.auth_token_data = None;
    }
}
