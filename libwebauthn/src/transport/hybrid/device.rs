//! [`Device`] impls opening a [`CableChannel`] to a PXP device.
use async_trait::async_trait;
use libwebauthn_pxp::{CableUpdate, ConnectTarget, UpdateSink};
use tokio::sync::broadcast;
use tracing::{debug, trace, warn};

use super::channel::{CableChannel, CableUxUpdate};
use super::error::CableError;
use super::known_devices::CableKnownDevice;
use super::qr_code_device::CableQrCodeDevice;
use super::Cable;
use crate::transport::{ChannelSettings, Device};
use crate::webauthn::error::WebAuthnError;

/// Forwards PXP connection updates onto the channel's UX update stream.
struct UxUpdateForwarder(broadcast::Sender<CableUxUpdate>);

impl UpdateSink for UxUpdateForwarder {
    fn send_update(&self, update: CableUpdate) {
        trace!("Sending UX update");
        if let Err(err) = self.0.send(CableUxUpdate::CableUpdate(update)) {
            warn!(?err, "No receivers found for UX update.");
        }
    }
}

fn open_channel(target: ConnectTarget, settings: ChannelSettings) -> CableChannel {
    let (ux_update_sender, _) = broadcast::channel(16);
    let tunnel = libwebauthn_pxp::connect(target, UxUpdateForwarder(ux_update_sender.clone()));
    CableChannel {
        tunnel,
        ux_update_sender,
        persistent_token_store: settings.persistent_token_store,
    }
}

#[async_trait]
impl<'d> Device<'d, Cable, CableChannel> for CableQrCodeDevice {
    async fn channel(
        &'d mut self,
        settings: ChannelSettings,
    ) -> Result<CableChannel, WebAuthnError<CableError>> {
        Ok(open_channel(self.clone().into(), settings))
    }
}

#[async_trait]
impl<'d> Device<'d, Cable, CableChannel> for CableKnownDevice {
    async fn channel(
        &'d mut self,
        settings: ChannelSettings,
    ) -> Result<CableChannel, WebAuthnError<CableError>> {
        debug!(?self.device_info.tunnel_domain, "Creating channel to tunnel server");
        Ok(open_channel(self.clone().into(), settings))
    }
}
