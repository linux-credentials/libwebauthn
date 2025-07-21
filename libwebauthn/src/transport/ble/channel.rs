use std::convert::TryInto;
use std::fmt::{Display, Formatter};
use std::time::Duration;

use crate::fido::{FidoProtocol, FidoRevision};
use crate::proto::ctap1::apdu::{ApduRequest, ApduResponse};
use crate::proto::ctap2::cbor::{CborRequest, CborResponse};
use crate::proto::CtapError;
use crate::transport::ble::btleplug;
use crate::transport::channel::{AuthTokenData, Channel, ChannelStatus, Ctap2AuthTokenStore};
use crate::transport::device::SupportedProtocols;
use crate::transport::error::TransportError;
use crate::webauthn::error::Error;
use crate::UvUpdate;

use super::btleplug::manager::SupportedRevisions;
use super::btleplug::Connection;
use super::framing::{BleCommand, BleFrame};
use super::BleDevice;

use async_trait::async_trait;
use tokio::sync::broadcast;
use tracing::{debug, instrument, trace, Level};

#[derive(Debug)]
pub struct BleChannel<'a> {
    status: ChannelStatus,
    device: &'a BleDevice,
    connection: Connection,
    revision: FidoRevision,
    auth_token_data: Option<AuthTokenData>,
    ux_update_sender: broadcast::Sender<UvUpdate>,
}

impl<'a> BleChannel<'a> {
    pub async fn new(
        device: &'a BleDevice,
        revisions: &SupportedRevisions,
    ) -> Result<BleChannel<'a>, Error> {
        let (ux_update_sender, _) = broadcast::channel(16);

        let revision = revisions
            .select_protocol(FidoProtocol::U2F)
            .ok_or(Error::Transport(TransportError::NegotiationFailed))?;
        let connection = btleplug::connect(&device.btleplug_device.peripheral, &revision)
            .await
            .or(Err(Error::Transport(TransportError::ConnectionFailed)))?;
        let channel = BleChannel {
            status: ChannelStatus::Ready,
            device,
            connection,
            revision,
            auth_token_data: None,
            ux_update_sender,
        };
        channel
            .connection
            .subscribe()
            .await
            .or(Err(Error::Transport(TransportError::TransportUnavailable)))?;
        Ok(channel)
    }
}

impl Display for BleChannel<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.device.fmt(f)
    }
}

#[async_trait]
impl<'a> Channel for BleChannel<'a> {
    type UxUpdate = UvUpdate;

    async fn supported_protocols(&self) -> Result<SupportedProtocols, Error> {
        Ok(self.revision.into())
    }

    async fn status(&self) -> ChannelStatus {
        self.status
    }

    async fn close(&mut self) {
        let _x = self.device;
        todo!()
    }

    #[instrument(level = Level::DEBUG, skip_all)]
    async fn apdu_send(&self, request: &ApduRequest, _timeout: Duration) -> Result<(), Error> {
        debug!({rev = ?self.revision}, "Sending APDU request");
        trace!(?request);

        let request_apdu_packet = request.raw_long().or(Err(TransportError::InvalidFraming))?;
        let request_frame = BleFrame::new(BleCommand::Msg, &request_apdu_packet);
        self.connection
            .frame_send(&request_frame)
            .await
            .or(Err(Error::Transport(TransportError::ConnectionFailed)))?;
        Ok(())
    }

    #[instrument(level = Level::DEBUG, skip_all)]
    async fn apdu_recv(&self, _timeout: Duration) -> Result<ApduResponse, Error> {
        let response_frame = self
            .connection
            .frame_recv()
            .await
            .or(Err(Error::Transport(TransportError::ConnectionFailed)))?;
        match response_frame.cmd {
            BleCommand::Error => return Err(Error::Transport(TransportError::InvalidFraming)), // Encapsulation layer error
            BleCommand::Cancel => return Err(Error::Ctap(CtapError::KeepAliveCancel)),
            BleCommand::Keepalive | BleCommand::Ping => return Err(Error::Ctap(CtapError::Other)), // Unexpected
            BleCommand::Msg => {}
        }
        let response_apdu_packet = &response_frame.data;
        let response_apdu: ApduResponse = response_apdu_packet
            .try_into()
            .or(Err(TransportError::InvalidFraming))?;

        debug!("Received APDU response");
        trace!(?response_apdu);
        Ok(response_apdu)
    }

    #[instrument(level = Level::DEBUG, skip_all)]
    async fn cbor_send(
        &mut self,
        request: &CborRequest,
        _timeout: std::time::Duration,
    ) -> Result<(), Error> {
        debug!("Sending CBOR request");
        trace!(?request);

        let cbor_request = request
            .raw_long()
            .map_err(|e| TransportError::IoError(e.kind()))?;
        let request_frame = BleFrame::new(BleCommand::Msg, &cbor_request);
        self.connection
            .frame_send(&request_frame)
            .await
            .or(Err(Error::Transport(TransportError::ConnectionFailed)))?;
        Ok(())
    }

    #[instrument(level = Level::DEBUG, skip_all)]
    async fn cbor_recv(&mut self, _timeout: std::time::Duration) -> Result<CborResponse, Error> {
        let response_frame = self
            .connection
            .frame_recv()
            .await
            .or(Err(Error::Transport(TransportError::ConnectionFailed)))?;
        match response_frame.cmd {
            BleCommand::Error => return Err(Error::Transport(TransportError::InvalidFraming)), // Encapsulation layer error
            BleCommand::Cancel => return Err(Error::Ctap(CtapError::KeepAliveCancel)),
            BleCommand::Keepalive | BleCommand::Ping => return Err(Error::Ctap(CtapError::Other)), // Unexpected
            BleCommand::Msg => {}
        }
        let cbor_response_packet = &response_frame.data;
        let cbor_response: CborResponse = cbor_response_packet
            .try_into()
            .or(Err(TransportError::InvalidFraming))?;

        debug!("Received CBOR response");
        trace!(?cbor_response);
        Ok(cbor_response)
    }

    fn get_ux_update_sender(&self) -> &broadcast::Sender<Self::UxUpdate> {
        &self.ux_update_sender
    }
}

impl Ctap2AuthTokenStore for BleChannel<'_> {
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
