use std::io::Cursor as IOCursor;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use btleplug::api::{Peripheral as _, ValueNotification, WriteType};
use btleplug::platform::Peripheral;
use byteorder::{BigEndian, ReadBytesExt};
use futures::stream::{Stream, StreamExt};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{debug, info, instrument, trace, warn};

use super::device::FidoEndpoints;
use super::gatt::write_type_for;
use super::Error;
use crate::fido::FidoRevision;
use crate::transport::ble::framing::{
    BleCommand, BleFrame as Frame, BleFrameParser, BleFrameParserResult,
};

type NotificationStream = Pin<Box<dyn Stream<Item = ValueNotification> + Send>>;

#[derive(Clone)]
pub struct Connection {
    pub peripheral: Peripheral,
    pub services: FidoEndpoints,
    /// `fidoStatus` is Notify-only (CTAP 2.2 §11.4); we consume notifications
    /// rather than issue GATT Read.
    notifications: Arc<Mutex<NotificationStream>>,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("peripheral", &self.peripheral)
            .field("services", &self.services)
            .finish_non_exhaustive()
    }
}

impl Connection {
    pub async fn new(
        peripheral: &Peripheral,
        services: &FidoEndpoints,
        revision: &FidoRevision,
    ) -> Result<Self, Error> {
        // Subscribe before opening the stream so early frames aren't dropped.
        peripheral
            .subscribe(&services.status)
            .await
            .or(Err(Error::OperationFailed))?;

        let status_uuid = services.status.uuid;
        let raw_stream = peripheral
            .notifications()
            .await
            .or(Err(Error::OperationFailed))?;
        let notifications: NotificationStream = Box::pin(raw_stream.filter(move |n| {
            let matches = n.uuid == status_uuid;
            async move { matches }
        }));

        let connection = Self {
            peripheral: peripheral.to_owned(),
            services: services.clone(),
            notifications: Arc::new(Mutex::new(notifications)),
        };
        connection.select_fido_revision(revision).await?;
        Ok(connection)
    }

    async fn control_point_length(&self) -> Result<usize, Error> {
        let max_fragment_length = self
            .peripheral
            .read(&self.services.control_point_length)
            .await
            .or(Err(Error::OperationFailed))?;

        if max_fragment_length.len() != 2 {
            warn!(
                { len = max_fragment_length.len() },
                "Control point length endpoint returned an unexpected number of bytes",
            );
            return Err(Error::OperationFailed);
        }

        let mut cursor = IOCursor::new(max_fragment_length);
        let max_fragment_size = cursor
            .read_u16::<BigEndian>()
            .map_err(|_| Error::OperationFailed)? as usize;
        Ok(max_fragment_size)
    }

    pub async fn frame_send(&self, frame: &Frame) -> Result<(), Error> {
        let max_fragment_size = self.control_point_length().await?;
        let fragments = frame
            .fragments(max_fragment_size)
            .or(Err(Error::InvalidFraming))?;

        let write_type = write_type_for(&self.services.control_point);

        for (i, fragment) in fragments.iter().enumerate() {
            debug!({ fragment = i, len = fragment.len() }, "Sending fragment");
            trace!(?fragment);

            self.peripheral
                .write(&self.services.control_point, fragment, write_type)
                .await
                .or(Err(Error::OperationFailed))?;
        }

        Ok(())
    }

    pub(crate) async fn select_fido_revision(&self, revision: &FidoRevision) -> Result<(), Error> {
        let ack: u8 = *revision as u8;
        let write_type = write_type_for(&self.services.service_revision_bitfield);
        self.peripheral
            .write(&self.services.service_revision_bitfield, &[ack], write_type)
            .await
            .or(Err(Error::OperationFailed))?;

        info!(?revision, "Successfully selected FIDO revision");
        Ok(())
    }

    /// Sends a best-effort Cancel on `fidoControlPoint` using
    /// `WriteType::WithoutResponse` so cancellation never blocks.
    async fn send_cancel(&self) -> Result<(), Error> {
        let cancel_frame = Frame::new(BleCommand::Cancel, &[]);
        let max_fragment_size = self.control_point_length().await.unwrap_or(20);
        let fragments = cancel_frame
            .fragments(max_fragment_size)
            .or(Err(Error::InvalidFraming))?;
        for fragment in fragments {
            self.peripheral
                .write(
                    &self.services.control_point,
                    &fragment,
                    WriteType::WithoutResponse,
                )
                .await
                .or(Err(Error::OperationFailed))?;
        }
        Ok(())
    }

    #[instrument(skip_all)]
    pub async fn frame_recv(&self, op_timeout: Duration) -> Result<Frame, Error> {
        let mut parser = BleFrameParser::new();
        let mut stream = self.notifications.lock().await;

        loop {
            let fragment = match timeout(op_timeout, stream.next()).await {
                Ok(Some(notification)) => notification.value,
                Ok(None) => {
                    warn!("Notification stream ended unexpectedly");
                    return Err(Error::ConnectionFailed);
                }
                Err(_) => {
                    warn!(
                        ?op_timeout,
                        "Timed out waiting for fidoStatus notification; sending Cancel"
                    );
                    // Drop the lock so a late notification doesn't deadlock the cancel.
                    drop(stream);
                    if let Err(e) = self.send_cancel().await {
                        warn!(?e, "Failed to send Cancel after timeout");
                    }
                    return Err(Error::Timeout);
                }
            };

            debug!("Received fragment");
            trace!(?fragment);

            let status = parser.update(&fragment).or(Err(Error::InvalidFraming))?;
            match status {
                BleFrameParserResult::Done => {
                    let frame = parser.frame().or(Err(Error::InvalidFraming))?;
                    trace!(?frame, "Received frame");
                    match frame.cmd {
                        BleCommand::Keepalive => {
                            debug!("Received keep-alive from authenticator");
                            parser.reset();
                        }
                        BleCommand::Cancel => {
                            info!("Device canceled operation");
                            return Err(Error::Canceled);
                        }
                        BleCommand::Error => {
                            warn!("Received error frame");
                            return Err(Error::OperationFailed);
                        }
                        BleCommand::Ping => {
                            debug!("Ignoring ping from device");
                        }
                        BleCommand::Msg => {
                            debug!("Received operation response");
                            return Ok(frame);
                        }
                    }
                }
                BleFrameParserResult::MoreFragmentsExpected => {}
            }
        }
    }

    /// Enables notifications on `fidoStatus`. Idempotent.
    pub async fn subscribe(&self) -> Result<(), Error> {
        self.peripheral
            .subscribe(&self.services.status)
            .await
            .or(Err(Error::OperationFailed))
    }
}
