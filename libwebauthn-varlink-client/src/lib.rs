//! Client-side proxy for the `com.github.linux-credentials.webauthn` varlink interface, matching
//! `WebauthnService` in the `webauthd-link` server. Channel state is tracked server-side
//! per-connection (there's no client-visible channel id), so these calls take
//! no id/channel-identifying parameters.

use futures_util::Stream;
use zlink::proxy;

use libwebauthn_varlink_types::{
    Event, VarlinkAvailabilityReply, VarlinkError, VarlinkOperation, VarlinkQrCodeReply,
    VarlinkRequestOrigin, VarlinkTransportMode,
};

#[proxy("com.github.linux-credentials.webauthn")]
pub trait WebauthnProxy {
    async fn is_available(
        &mut self,
    ) -> zlink::Result<Result<VarlinkAvailabilityReply, VarlinkError>>;

    async fn future_device_connection(
        &mut self,
        operation: VarlinkOperation,
        transport: VarlinkTransportMode,
    ) -> zlink::Result<Result<VarlinkQrCodeReply, VarlinkError>>;

    #[zlink(more)]
    async fn await_connecting(
        &mut self,
    ) -> zlink::Result<impl Stream<Item = zlink::Result<Result<Event, VarlinkError>>>>;

    #[zlink(more)]
    async fn webauthn_make_credential(
        &mut self,
        origin: VarlinkRequestOrigin,
        request_json: String,
    ) -> zlink::Result<impl Stream<Item = zlink::Result<Result<Event, VarlinkError>>>>;

    async fn close_channel(&mut self) -> zlink::Result<Result<(), VarlinkError>>;

    async fn provide_pin(
        &mut self,
        token: String,
        pin: Option<String>,
    ) -> zlink::Result<Result<(), VarlinkError>>;
}
