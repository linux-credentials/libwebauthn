use std::io::Cursor as IOCursor;

use btleplug::api::{Peripheral as _, WriteType};
use btleplug::platform::Peripheral;
use byteorder::{BigEndian, ReadBytesExt};
use tracing::{debug, info, instrument, trace, warn};

use super::device::FidoEndpoints;
use super::Error;
use crate::fido::FidoRevision;
use crate::transport::ble::framing::{
    BleCommand, BleFrame as Frame, BleFrameParser, BleFrameParserResult,
};

#[derive(Debug, Clone)]
pub struct Connection {
    pub peripheral: Peripheral,
    pub services: FidoEndpoints,
}

impl Connection {
    pub async fn new(
        peripheral: &Peripheral,
        services: &FidoEndpoints,
        revision: &FidoRevision,
    ) -> Result<Self, Error> {
        let connection = Self {
            peripheral: peripheral.to_owned(),
            services: services.clone(),
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
        let max_fragment_size = cursor.read_u16::<BigEndian>().unwrap() as usize;
        Ok(max_fragment_size)
    }

    pub async fn frame_send(&self, frame: &Frame) -> Result<(), Error> {
        let max_fragment_size = self.control_point_length().await?;
        let fragments = frame
            .fragments(max_fragment_size)
            .or(Err(Error::InvalidFraming))?;

        for (i, fragment) in fragments.iter().enumerate() {
            debug!({ fragment = i, len = fragment.len() }, "Sending fragment");
            trace!(?fragment);

            self.peripheral
                .write(
                    &self.services.control_point,
                    fragment,
                    WriteType::WithoutResponse,
                )
                .await
                .or(Err(Error::OperationFailed))?;
        }

        Ok(())
    }

    pub(crate) async fn select_fido_revision(&self, revision: &FidoRevision) -> Result<(), Error> {
        let ack: u8 = revision.clone() as u8;
        self.peripheral
            .write(
                &self.services.service_revision_bitfield,
                &[ack],
                WriteType::WithoutResponse,
            )
            .await
            .or(Err(Error::OperationFailed))?;

        info!(?revision, "Successfully selected FIDO revision");
        Ok(())
    }

    #[instrument(skip_all)]
    pub async fn frame_recv(&self) -> Result<Frame, Error> {
        let mut parser = BleFrameParser::new();

        loop {
            let fragment = self.receive_fragment().await?;
            debug!("Received fragment");
            trace!(?fragment);

            let status = parser.update(&fragment).or(Err(Error::InvalidFraming))?;
            match status {
                BleFrameParserResult::Done => {
                    let frame = parser.frame().unwrap();
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

    async fn receive_fragment(&self) -> Result<Vec<u8>, Error> {
        self.peripheral
            .read(&self.services.status)
            .await
            .or(Err(Error::OperationFailed))
    }

    pub async fn subscribe(&self) -> Result<(), Error> {
        self.peripheral
            .subscribe(&self.services.status)
            .await
            .or(Err(Error::OperationFailed))
    }
}
