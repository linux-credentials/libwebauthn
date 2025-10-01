use apdu::core::HandleError;
use apdu::{command, Command, Response};
use apdu_core;
use async_trait::async_trait;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::sync::mpsc::{self, Sender};
#[allow(unused_imports)]
use tracing::{debug, instrument, trace, warn, Level};

use crate::proto::ctap1::apdu::{ApduRequest, ApduResponse};
use crate::proto::ctap2::cbor::{CborRequest, CborResponse};
use crate::proto::ctap2::Ctap2;
use crate::transport::channel::{AuthTokenData, Channel, ChannelStatus, Ctap2AuthTokenStore};
use crate::transport::device::SupportedProtocols;
use crate::transport::error::TransportError;
use crate::webauthn::Error;
use crate::UvUpdate;

use super::commands::{command_ctap_msg, command_get_response};

const SELECT_P1: u8 = 0x04;
const SELECT_P2: u8 = 0x00;
const FIDO2_AID: &[u8; 8] = b"\xa0\x00\x00\x06\x47\x2f\x00\x01";
const SW1_MORE_DATA: u8 = 0x61;

pub type CancelNfcOperation = ();

#[derive(thiserror::Error)]
pub enum NfcError {
    /// APDU error returned by the card.
    Apdu(#[from] apdu::Error),

    /// Unexpected error occurred on the device.
    Device(#[from] HandleError),
}

impl From<NfcError> for Error {
    fn from(input: NfcError) -> Self {
        trace!("{:?}", input);
        let output = match input {
            NfcError::Apdu(_apdu_error) => TransportError::InvalidFraming,
            NfcError::Device(_) => TransportError::ConnectionLost,
        };
        Error::Transport(output)
    }
}

impl Debug for NfcError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl Display for NfcError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NfcError::Apdu(e) => Display::fmt(e, f),
            NfcError::Device(e) => Display::fmt(e, f),
        }
    }
}

pub trait HandlerInCtx<Ctx> {
    /// Handles the APDU command in a specific context.
    /// Implementations must transmit the command to the card through a reader,
    /// then receive the response from them, returning length of the data written.
    fn handle_in_ctx(&mut self, ctx: Ctx, command: &[u8], response: &mut [u8])
        -> apdu_core::Result;
}

pub trait NfcBackend<Ctx>: HandlerInCtx<Ctx> + Display {}

#[derive(Debug, Clone)]
pub struct NfcChannelHandle {
    tx: Sender<CancelNfcOperation>,
}

impl NfcChannelHandle {
    pub async fn cancel_ongoing_operation(&self) {
        let _ = self.tx.send(()).await;
    }
}

pub struct NfcChannel<Ctx>
where
    Ctx: Copy + Sync,
{
    delegate: Box<dyn NfcBackend<Ctx> + Send + Sync>,
    auth_token_data: Option<AuthTokenData>,
    ux_update_sender: broadcast::Sender<UvUpdate>,
    handle: NfcChannelHandle,
    ctx: Ctx,
    apdu_response: Option<ApduResponse>,
    cbor_response: Option<CborResponse>,
    supported: SupportedProtocols,
    status: ChannelStatus,
}

impl<Ctx> Display for NfcChannel<Ctx>
where
    Ctx: Copy + Send + Sync,
{
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.delegate)
    }
}

impl<Ctx> NfcChannel<Ctx>
where
    Ctx: fmt::Debug + Display + Copy + Send + Sync,
{
    pub fn new(delegate: Box<dyn NfcBackend<Ctx> + Send + Sync>, ctx: Ctx) -> Self {
        let (ux_update_sender, _) = broadcast::channel(16);
        let (handle_tx, _handle_rx) = mpsc::channel(1);
        let handle = NfcChannelHandle { tx: handle_tx };
        NfcChannel {
            delegate,
            auth_token_data: None,
            ux_update_sender,
            handle,
            ctx,
            apdu_response: None,
            cbor_response: None,
            supported: SupportedProtocols {
                fido2: false,
                u2f: false,
            },
            status: ChannelStatus::Ready,
        }
    }

    pub fn get_handle(&self) -> NfcChannelHandle {
        self.handle.clone()
    }

    #[instrument(skip_all)]
    pub async fn wink(&mut self, _timeout: Duration) -> Result<bool, Error> {
        warn!("WINK capability is not supported");
        return Ok(false);
    }

    pub async fn select_fido2(&mut self) -> Result<(), Error> {
        // Given legacy support for CTAP1/U2F, the client MUST determine the capabilities of the device at the selection stage.
        let command = command::select_file(SELECT_P1, SELECT_P2, FIDO2_AID);
        let response = self.handle(self.ctx, command)?;
        let mut u2f = false;
        let mut fido2 = false;
        if response == b"FIDO_2_0" {
            //     If the authenticator ONLY implements CTAP2, the device SHALL respond with "FIDO_2_0", or 0x4649444f5f325f30.
            fido2 = true;
            // NOTE: Yubikeys seem to ignore this part of the specification and always return U2F_V2, even if U2F-NFC is disabled.
        } else if response == b"U2F_V2" {
            //     If the authenticator implements CTAP1/U2F, the version information SHALL be the string "U2F_V2", or 0x5532465f5632, to maintain backwards-compatibility with CTAP1/U2F-only clients.
            u2f = true;
            //     If the authenticator implements both CTAP1/U2F and CTAP2, the version information SHALL be the string "U2F_V2", or 0x5532465f5632, to maintain backwards-compatibility with CTAP1/U2F-only clients. CTAP2-aware clients MAY then issue a CTAP authenticatorGetInfo command to determine if the device supports CTAP2 or not.
            fido2 = self.ctap2_get_info().await.is_ok();
        }

        self.supported = SupportedProtocols { u2f, fido2 };

        Ok(())
    }

    fn handle_in_ctx(
        &mut self,
        ctx: Ctx,
        command_buf: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, NfcError> {
        let res = self.delegate.handle_in_ctx(ctx, command_buf, buf)?;
        Ok(res)
    }

    pub fn handle<'a>(
        &'a mut self,
        ctx: Ctx,
        command: impl Into<Command<'a>>,
    ) -> Result<Vec<u8>, NfcError> {
        let command = command.into();
        let command_buf = Vec::from(command);

        let mut buf = [0u8; 1024];
        let mut rapdu = Vec::new();

        let len = self.handle_in_ctx(ctx, &command_buf, &mut buf)?;
        let mut resp = Response::from(&buf[..len]);

        let (mut sw1, mut sw2) = resp.trailer;
        rapdu.extend_from_slice(resp.payload);

        while sw1 == SW1_MORE_DATA {
            let get_response_cmd = command_get_response(0x00, 0x00, sw2);
            let get_response_buf = Vec::from(get_response_cmd);
            let len = self.handle_in_ctx(ctx, &get_response_buf, &mut buf)?;
            resp = Response::from(&buf[..len]);
            (sw1, sw2) = resp.trailer;
            rapdu.extend_from_slice(resp.payload);
        }

        rapdu.extend_from_slice(&[sw1, sw2]);
        Result::from(Response::from(rapdu.as_slice()))
            .map(|p| p.to_vec())
            .map_err(|e| {
                trace!("map_err {:?}", e);
                apdu::Error::from(e).into()
            })
    }

    #[instrument(skip_all)]
    pub async fn blink_and_wait_for_user_presence(
        &mut self,
        _timeout: Duration,
    ) -> Result<bool, Error> {
        unimplemented!()
    }
}

#[async_trait]
impl<Ctx> Channel for NfcChannel<Ctx>
where
    Ctx: Copy + Send + Sync + fmt::Debug + Display,
{
    type UxUpdate = UvUpdate;

    async fn supported_protocols(&self) -> Result<SupportedProtocols, Error> {
        Ok(self.supported)
    }

    async fn status(&self) -> ChannelStatus {
        self.status
    }

    async fn close(&mut self) {
        todo!("close")
    }

    #[instrument(level = Level::DEBUG, skip_all)]
    async fn apdu_send(&mut self, request: &ApduRequest, _timeout: Duration) -> Result<(), Error> {
        let resp = self.handle(self.ctx, request)?;
        trace!("apdu_send {:?}", resp);

        let apdu_response = ApduResponse::new_success(&resp);
        self.apdu_response = Some(apdu_response);
        Ok(())
    }

    #[instrument(level = Level::DEBUG, skip_all)]
    async fn apdu_recv(&mut self, _timeout: Duration) -> Result<ApduResponse, Error> {
        self.apdu_response
            .take()
            .ok_or(Error::Transport(TransportError::InvalidFraming))
    }

    #[instrument(level = Level::DEBUG, skip_all)]
    async fn cbor_send(
        &mut self,
        request: &CborRequest,
        _timeout: std::time::Duration,
    ) -> Result<(), Error> {
        let data = &request.ctap_hid_data();
        let mut rest: &[u8] = data;

        while rest.len() > 250 {
            let to_send = &rest[..250];
            rest = &rest[250..];
            let ctap_msg = command_ctap_msg(true, to_send);
            let resp = self.handle(self.ctx, ctap_msg)?;
            trace!("cbor_send has_more {:?} {:?}", to_send, resp);
        }

        let ctap_msg = command_ctap_msg(false, rest);
        let resp = self.handle(self.ctx, ctap_msg)?;
        trace!("cbor_send {:?} {:?}", rest, resp);

        // FIXME check for SW_UPDATE?

        // let mut rapdu_buf = [0; pcsc::MAX_BUFFER_SIZE_EXTENDED];
        // let (mut resp, mut sw1, mut sw2) = self.card
        //     .chain_apdus(0x80, 0x10, 0x80, 0x00, data, &mut rapdu_buf)
        //     .expect("APDU exchange failed");

        // loop {
        //     while (sw1, sw2) == SW_UPDATE {
        //         // ka_status = STATUS(resp[0])
        //         // if on_keepalive and last_ka != ka_status:
        //         //     last_ka = ka_status
        //         //     on_keepalive(ka_status)
        //         // NFCCTAP_GETRESPONSE

        //         (resp, sw1, sw2) = self.card
        //             .chain_apdus(0x80, 0x11, 0x00, 0x00, &[], &mut rapdu_buf).expect("APDU chained exchange failed");
        //         debug!("Error {:?} {:?}", sw1, sw2);
        //     }

        //     if (sw1, sw2) != SW_SUCCESS {
        //         return Err(Error::Transport(TransportError::InvalidFraming));
        //     }

        let cbor_response = CborResponse::try_from(&resp)
            .or(Err(Error::Transport(TransportError::InvalidFraming)))?;
        self.cbor_response = Some(cbor_response);
        Ok(())
    }

    #[instrument(level = Level::DEBUG, skip_all)]
    async fn cbor_recv(&mut self, _timeout: std::time::Duration) -> Result<CborResponse, Error> {
        self.cbor_response
            .take()
            .ok_or(Error::Transport(TransportError::InvalidFraming))
    }

    fn get_ux_update_sender(&self) -> &broadcast::Sender<UvUpdate> {
        &self.ux_update_sender
    }
}

impl<Ctx> Ctap2AuthTokenStore for NfcChannel<Ctx>
where
    Ctx: Copy + Send + Sync,
{
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
