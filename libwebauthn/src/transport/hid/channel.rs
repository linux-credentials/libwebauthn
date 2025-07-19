use std::convert::TryFrom;
use std::fmt::{Debug, Display, Formatter};
use std::io::{Cursor as IOCursor, Seek, SeekFrom};
use std::ops::DerefMut;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use byteorder::{BigEndian, ReadBytesExt};
use hidapi::HidDevice as HidApiDevice;
use rand::{thread_rng, Rng};
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::sleep;
use tracing::{debug, info, instrument, trace, warn, Level};

#[cfg(feature = "virtual-hid-device")]
use tokio::net::UdpSocket;

use crate::proto::ctap1::apdu::{ApduRequest, ApduResponse};
use crate::proto::ctap1::{Ctap1, Ctap1RegisterRequest};
use crate::proto::ctap2::cbor::{CborRequest, CborResponse};
use crate::proto::ctap2::{Ctap2, Ctap2MakeCredentialRequest};
use crate::proto::CtapError;
use crate::transport::channel::{AuthTokenData, Channel, ChannelStatus, Ctap2AuthTokenStore};
use crate::transport::device::SupportedProtocols;
use crate::transport::error::TransportError;
use crate::transport::hid::framing::{
    HidCommand, HidMessage, HidMessageParser, HidMessageParserState,
};
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

// Some devices fail when sending a WINK command followed immediately
// by a CBOR command, so we want to ensure we wait some time after winking.
const WINK_MIN_WAIT: Duration = Duration::from_secs(2);

pub type CancelHidOperation = ();
enum OpenHidDevice {
    HidApiDevice(Arc<Mutex<(HidApiDevice, mpsc::Receiver<CancelHidOperation>)>>),
    #[cfg(feature = "virtual-hid-device")]
    VirtualDevice,
}

#[derive(Debug, Clone)]
pub struct HidChannelHandle {
    tx: Sender<CancelHidOperation>,
}

impl HidChannelHandle {
    pub async fn cancel_ongoing_operation(&self) {
        let _ = self.tx.send(()).await;
    }
}

pub struct HidChannel<'d> {
    status: ChannelStatus,
    device: &'d HidDevice,
    open_device: OpenHidDevice,
    init: InitResponse,
    auth_token_data: Option<AuthTokenData>,
    tx: mpsc::Sender<UvUpdate>,
    handle: HidChannelHandle,
}

impl<'d> HidChannel<'d> {
    pub async fn new(
        device: &'d HidDevice,
        tx: mpsc::Sender<UvUpdate>,
    ) -> Result<HidChannel<'d>, Error> {
        let (handle_tx, handle_rx) = mpsc::channel(1);
        let handle = HidChannelHandle { tx: handle_tx };

        let mut channel = Self {
            status: ChannelStatus::Ready,
            device,
            open_device: match device.backend {
                HidBackendDevice::HidApiDevice(_) => {
                    let hidapi_device = Self::hid_open(device)?;
                    OpenHidDevice::HidApiDevice(Arc::new(Mutex::new((hidapi_device, handle_rx))))
                }
                #[cfg(feature = "virtual-hid-device")]
                HidBackendDevice::VirtualDevice(_) => OpenHidDevice::VirtualDevice,
            },
            init: InitResponse::default(),
            auth_token_data: None,
            tx,
            handle,
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
        if cfg!(not(feature = "virtual-hid-device")) {
            let _ = self.hid_recv(timeout).await?;
        }

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
        cursor.seek(SeekFrom::Start(8)).unwrap();

        let init = InitResponse {
            cid: cursor.read_u32::<BigEndian>().unwrap(),
            protocol_version: cursor.read_u8().unwrap(),
            version_major: cursor.read_u8().unwrap(),
            version_minor: cursor.read_u8().unwrap(),
            version_build: cursor.read_u8().unwrap(),
            caps: Caps::from_bits_truncate(cursor.read_u8().unwrap()),
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
            #[cfg(feature = "virtual-hid-device")]
            HidBackendDevice::VirtualDevice(_) => unreachable!(),
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
                let (device, cancel_rx) = guard.deref_mut();
                let response = Self::hid_send_hidapi(device, cancel_rx, msg);
                if matches!(response, Err(Error::Platform(PlatformError::Cancelled))) {
                    // Using hid_send_hidapi directly, instead of hid_cancel, to avoid recursion
                    let _ = Self::hid_send_hidapi(
                        device,
                        cancel_rx,
                        &HidMessage::new(self.init.cid, HidCommand::Cancel, &[]),
                    );
                }
                response
            }
            #[cfg(feature = "virtual-hid-device")]
            OpenHidDevice::VirtualDevice => Self::hid_send_virtual(msg).await,
        }
    }

    fn hid_send_hidapi(
        device: &hidapi::HidDevice,
        cancel_rx: &mut Receiver<CancelHidOperation>,
        msg: &HidMessage,
    ) -> Result<(), Error> {
        let packets = msg
            .packets(PACKET_SIZE)
            .or(Err(Error::Transport(TransportError::InvalidFraming)))?;
        for (i, packet) in packets.iter().enumerate() {
            if !matches!(cancel_rx.try_recv(), Err(TryRecvError::Empty)) {
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

    #[cfg(feature = "virtual-hid-device")]
    async fn hid_send_virtual(msg: &HidMessage) -> Result<(), Error> {
        // https://github.com/solokeys/python-fido2/commit/4964d98ca6d0cfc24cd49926521282b8e92c598d
        let socket = UdpSocket::bind("127.0.0.1:7112")
            .await
            .or(Err(Error::Transport(TransportError::TransportUnavailable)))?;

        debug!({ cmd = ?msg.cmd, payload_len = msg.payload.len() }, "U2F HID request to UDP virtual device");
        trace!(?msg);

        let packets = msg
            .packets(PACKET_SIZE)
            .or(Err(Error::Transport(TransportError::InvalidFraming)))?;
        for (i, packet) in packets.iter().enumerate() {
            let mut report: Vec<u8> = vec![];
            report.extend(packet);
            report.extend(vec![0; PACKET_SIZE - packet.len()]);

            debug!(
                { packet = i, len = report.len() },
                "Sending packet as HID report",
            );
            trace!(?packet);

            socket
                .send_to(&report, "127.0.0.1:8111")
                .await
                .or(Err(Error::Transport(TransportError::ConnectionLost)))?;
        }

        Ok(())
    }

    #[instrument(skip_all)]
    pub async fn hid_recv(&self, timeout: Duration) -> Result<HidMessage, Error> {
        loop {
            let response = match &self.open_device {
                OpenHidDevice::HidApiDevice(hidapi_device) => {
                    let device = Arc::clone(hidapi_device);
                    // The HID device will block when waiting for a user to
                    // interact with the device, so mark the task as blocking to
                    // allow other tasks to complete.
                    // Note that we're just using spawn_blocking() on hid_recv(), not on hid_send(),
                    // since implementing this on hid_send and would cause unnecessary copies/locking.
                    tokio::task::spawn_blocking(move || {
                        let Ok(mut guard) = device.lock() else {
                            warn!("Poisoned lock on HID API device");
                            return Err(Error::Transport(TransportError::ConnectionLost));
                        };
                        let (device, cancel_rx) = guard.deref_mut();
                        Self::hid_recv_hidapi(device, cancel_rx, timeout)
                    })
                    .await
                    .expect("HID read not to panic.")
                }
                #[cfg(feature = "virtual-hid-device")]
                OpenHidDevice::VirtualDevice => Self::hid_recv_virtual(timeout).await,
            };

            match response {
                Ok(HidMessage {
                    cmd: HidCommand::KeepAlive,
                    ..
                }) => {
                    debug!("Ignoring HID keep-alive");
                    continue;
                }
                Err(Error::Platform(PlatformError::Cancelled)) => {
                    let _ = self.hid_cancel().await;
                    break response;
                }
                _ => break response,
            }
        }
    }

    fn hid_recv_hidapi(
        device: &hidapi::HidDevice,
        cancel_rx: &mut Receiver<CancelHidOperation>,
        timeout: Duration,
    ) -> Result<HidMessage, Error> {
        let mut parser = HidMessageParser::new();
        loop {
            if !matches!(cancel_rx.try_recv(), Err(TryRecvError::Empty)) {
                return Err(Error::Platform(PlatformError::Cancelled));
            }

            let mut report = [0; PACKET_SIZE];
            device
                .read_timeout(&mut report, timeout.as_millis() as i32)
                .or(Err(Error::Transport(TransportError::ConnectionLost)))?;
            debug!({ len = report.len() }, "Received HID report");
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

    #[cfg(feature = "virtual-hid-device")]
    async fn hid_recv_virtual(_timeout: Duration) -> Result<HidMessage, Error> {
        // https://github.com/solokeys/python-fido2/commit/4964d98ca6d0cfc24cd49926521282b8e92c598d
        let socket = UdpSocket::bind("127.0.0.1:7112")
            .await
            .or(Err(Error::Transport(TransportError::TransportUnavailable)))?;

        let mut parser = HidMessageParser::new();
        loop {
            let mut report = [0; PACKET_SIZE];
            socket
                .recv_from(&mut report)
                .await
                .or(Err(Error::Transport(TransportError::ConnectionLost)))?;
            debug!(
                { len = report.len() },
                "Received HID report from UDP virtual device"
            );
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
        debug!({ cmd = ?response.cmd }, "Parsed U2F HID response from UDP virtual device");
        trace!(?response);

        Ok(response)
    }
}

impl Drop for HidChannel<'_> {
    #[instrument(level = Level::DEBUG, skip_all, fields(dev = %self.device))]
    fn drop(&mut self) {
        #[cfg(feature = "virtual-hid-device")]
        if let HidBackendDevice::VirtualDevice(_) = self.device.backend {
            return;
        }

        if let Err(err) = futures::executor::block_on(self.hid_cancel()) {
            warn!(
                ?err,
                "Failed to send hid_cancel on the channel being dropped"
            )
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

    async fn close(&mut self) {
        ()
    }

    async fn apdu_send(
        &self,
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

    async fn apdu_recv(&self, timeout: std::time::Duration) -> Result<ApduResponse, Error> {
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

    fn get_ux_update_sender(&self) -> &mpsc::Sender<UvUpdate> {
        &self.tx
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
