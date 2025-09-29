use async_trait::async_trait;
use std::{collections::VecDeque, fmt::Display, time::Duration};
use tokio::sync::broadcast;

use crate::{
    proto::{
        ctap1::apdu::{ApduRequest, ApduResponse},
        ctap2::cbor::{CborRequest, CborResponse},
    },
    transport::{
        device::SupportedProtocols, AuthTokenData, Channel, ChannelStatus, Ctap2AuthTokenStore,
    },
    webauthn::Error,
    UvUpdate,
};

pub struct MockChannel {
    expected_requests: VecDeque<CborRequest>,
    responses: VecDeque<CborResponse>,
    auth_token_data: Option<AuthTokenData>,
    ux_update_sender: broadcast::Sender<UvUpdate>,
}

impl MockChannel {
    pub fn new() -> Self {
        let (ux_update_sender, _) = broadcast::channel(16);
        Self {
            expected_requests: VecDeque::new(),
            responses: VecDeque::new(),
            auth_token_data: None,
            ux_update_sender,
        }
    }

    pub fn push_command_pair(&mut self, expected_request: CborRequest, response: CborResponse) {
        self.expected_requests.push_front(expected_request);
        self.responses.push_front(response);
    }
}

impl Ctap2AuthTokenStore for MockChannel {
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

impl Display for MockChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TestChannel")
    }
}

#[async_trait]
impl Channel for MockChannel {
    type UxUpdate = UvUpdate;

    fn get_ux_update_sender(&self) -> &broadcast::Sender<Self::UxUpdate> {
        &self.ux_update_sender
    }

    async fn supported_protocols(&self) -> Result<SupportedProtocols, Error> {
        Ok(SupportedProtocols {
            u2f: false,
            fido2: true,
        })
    }
    async fn status(&self) -> ChannelStatus {
        unimplemented!();
    }
    async fn close(&mut self) {
        unimplemented!();
    }

    async fn apdu_send(&mut self, _request: &ApduRequest, _timeout: Duration) -> Result<(), Error> {
        unimplemented!();
    }
    async fn apdu_recv(&mut self, _timeout: Duration) -> Result<ApduResponse, Error> {
        unimplemented!();
    }

    async fn cbor_send(&mut self, request: &CborRequest, _timeout: Duration) -> Result<(), Error> {
        let expected = self
            .expected_requests
            .pop_back()
            .expect("No expected request found, but one was sent");
        assert_eq!(
            &expected,
            request,
            "{} items still in the queue",
            self.expected_requests.len()
        );
        Ok(())
    }
    async fn cbor_recv(&mut self, _timeout: Duration) -> Result<CborResponse, Error> {
        let response = self
            .responses
            .pop_back()
            .expect("No response found, but one was requested");
        Ok(response)
    }
}
