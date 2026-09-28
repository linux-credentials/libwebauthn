//! [`Device`] impls opening a [`HybridChannel`] to a PXP device.
use async_trait::async_trait;
use libwebauthn_pxp::{ConnectTarget, PxpUpdate, UpdateSink};
use tokio::sync::broadcast;
use tracing::{debug, trace, warn};

use super::channel::{HybridChannel, HybridUxUpdate};
use super::error::PxpError;
use super::known_devices::PxpKnownDevice;
use super::qr_code_device::PxpQrCodeDevice;
use super::Hybrid;
use crate::transport::{ChannelSettings, Device};
use crate::webauthn::error::WebAuthnError;

/// Forwards PXP connection updates onto the channel's UX update stream.
struct UxUpdateForwarder(broadcast::Sender<HybridUxUpdate>);

impl UpdateSink for UxUpdateForwarder {
    fn send_update(&self, update: PxpUpdate) {
        trace!("Sending UX update");
        if let Err(err) = self.0.send(HybridUxUpdate::PxpUpdate(update)) {
            warn!(?err, "No receivers found for UX update.");
        }
    }
}

fn open_channel(target: ConnectTarget, settings: ChannelSettings) -> HybridChannel {
    let (ux_update_sender, _) = broadcast::channel(16);
    let tunnel = libwebauthn_pxp::connect(target, UxUpdateForwarder(ux_update_sender.clone()));
    HybridChannel {
        tunnel,
        ux_update_sender,
        persistent_token_store: settings.persistent_token_store,
    }
}

#[async_trait]
impl<'d> Device<'d, Hybrid, HybridChannel> for PxpQrCodeDevice {
    async fn channel(
        &'d mut self,
        settings: ChannelSettings,
    ) -> Result<HybridChannel, WebAuthnError<PxpError>> {
        Ok(open_channel(self.clone().into(), settings))
    }
}

#[async_trait]
impl<'d> Device<'d, Hybrid, HybridChannel> for PxpKnownDevice {
    async fn channel(
        &'d mut self,
        settings: ChannelSettings,
    ) -> Result<HybridChannel, WebAuthnError<PxpError>> {
        debug!(?self.device_info.tunnel_domain, "Creating channel to tunnel server");
        Ok(open_channel(self.clone().into(), settings))
    }
}
