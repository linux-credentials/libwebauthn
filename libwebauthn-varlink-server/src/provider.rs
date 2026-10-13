//! The seam between the varlink service and libwebauthn's transports. The
//! service runs ceremonies on whatever channels a [`ChannelProvider`] opens:
//! the daemon uses [`CableProvider`], tests plug in a virtual authenticator.
//!
//! zlink's `#[service]` macro does not support type parameters on the service
//! itself, so the provider and its channels are trait objects rather than
//! generic parameters.

use futures_util::future::BoxFuture;
use libwebauthn::ops::webauthn::{MakeCredentialRequest, MakeCredentialResponse};
use libwebauthn::transport::cable::channel::{CableChannel, CableUxUpdate};
use libwebauthn::transport::cable::qr_code_device::CableQrCodeDevice;
use libwebauthn::transport::{Channel as _, ChannelSettings, Device as _};
use libwebauthn::webauthn::WebAuthn as _;
use libwebauthn_varlink_types::{VarlinkError, VarlinkOperation, VarlinkTransportMode};
use tokio::sync::broadcast::{self, error::RecvError};

/// Opens the channels the service runs ceremonies on.
pub trait ChannelProvider: Send + Sync {
    /// Whether the transport can be used on this system at all.
    fn is_available(&self) -> BoxFuture<'_, bool>;

    /// Opens a channel for an `operation` ceremony. Returns once the channel
    /// exists, without waiting for an authenticator to connect to it.
    fn open(
        &self,
        operation: VarlinkOperation,
        transport: VarlinkTransportMode,
    ) -> BoxFuture<'_, Result<OpenedChannel, VarlinkError>>;
}

/// A freshly opened channel, together with the QR code that lets an
/// authenticator connect to it.
pub struct OpenedChannel {
    pub qr_contents: String,
    pub channel: Box<dyn CeremonyChannel>,
}

/// A channel the service can run ceremonies on, with its transport erased.
pub trait CeremonyChannel: Send {
    /// Subscribes to the channel's UX updates. Updates sent before the call
    /// are not received.
    fn updates(&self) -> Box<dyn UpdateReceiver>;

    fn make_credential<'a>(
        &'a mut self,
        request: &'a MakeCredentialRequest,
    ) -> BoxFuture<'a, Result<MakeCredentialResponse, VarlinkError>>;
}

/// Receives a channel's UX updates. caBLE's update type is the most general
/// one (UV updates plus connection progress), so every channel's updates are
/// converted into it.
pub trait UpdateReceiver: Send {
    fn recv(&mut self) -> BoxFuture<'_, Result<CableUxUpdate, RecvError>>;
}

impl<T> UpdateReceiver for broadcast::Receiver<T>
where
    T: Clone + Send + Into<CableUxUpdate>,
{
    fn recv(&mut self) -> BoxFuture<'_, Result<CableUxUpdate, RecvError>> {
        Box::pin(async move { broadcast::Receiver::recv(self).await.map(Into::into) })
    }
}

/// Opens transient hybrid (caBLE) channels, advertised through a QR code.
pub struct CableProvider;

impl ChannelProvider for CableProvider {
    fn is_available(&self) -> BoxFuture<'_, bool> {
        Box::pin(libwebauthn::transport::cable::is_available())
    }

    fn open(
        &self,
        operation: VarlinkOperation,
        transport: VarlinkTransportMode,
    ) -> BoxFuture<'_, Result<OpenedChannel, VarlinkError>> {
        Box::pin(async move {
            // As in libwebauthn's own example, the channel is opened right
            // away: that only spawns the connecting task, it does not block on
            // a phone showing up.
            let mut device = CableQrCodeDevice::new_transient(operation.into(), transport.into())
                .map_err(VarlinkError::from)?;
            let qr_contents = device.qr_code.to_string();
            let channel = device
                .channel(ChannelSettings::default())
                .await
                .map_err(VarlinkError::from)?;
            Ok(OpenedChannel {
                qr_contents,
                channel: Box::new(channel),
            })
        })
    }
}

impl CeremonyChannel for CableChannel {
    fn updates(&self) -> Box<dyn UpdateReceiver> {
        Box::new(self.get_ux_update_receiver())
    }

    fn make_credential<'a>(
        &'a mut self,
        request: &'a MakeCredentialRequest,
    ) -> BoxFuture<'a, Result<MakeCredentialResponse, VarlinkError>> {
        Box::pin(async move {
            self.webauthn_make_credential(request)
                .await
                .map_err(VarlinkError::from)
        })
    }
}
