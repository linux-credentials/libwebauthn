mod device;
mod pipe;

use super::hid::framing::HidCommand;
use super::hid::framing::HidMessage;
use crate::webauthn::Error;
use num_enum::TryFromPrimitive;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub(crate) struct VirtHidDevice {
    storage_dir: Arc<tempfile::TempDir>,
    response: Option<HidMessage>,
}

impl VirtHidDevice {
    pub fn new() -> Self {
        let storage_dir =
            tempfile::tempdir().expect("Failed to create temp. dir for virtual device storage");
        Self {
            response: None,
            storage_dir: Arc::new(storage_dir),
        }
    }

    pub fn virt_send(&mut self, msg: &HidMessage) -> Result<(), Error> {
        let mut response = msg.clone();
        match device::run_ctaphid(self.storage_dir.path(), |device| {
            match msg.cmd {
                HidCommand::Ping => device.ping(&msg.payload).map(|_| Vec::new()),
                HidCommand::Msg => device.ctap1(&msg.payload),
                // HidCommand::Lock => device.lock(duration),
                HidCommand::Init => {
                    let mut payload = msg.payload.clone();
                    // Fake channel ID
                    payload.extend_from_slice(&[1, 2, 3, 4]);
                    payload.push(device.protocol_version());
                    let versions = device.device_version();
                    payload.push(versions.major);
                    payload.push(versions.minor);
                    payload.push(versions.build);
                    payload.push(device.capabilities().bits());
                    Ok(payload)
                }
                HidCommand::Wink => device.wink().map(|_| Vec::new()),
                HidCommand::Cbor => {
                    device
                        .ctap2(msg.payload[0], &msg.payload[1..])
                        .map(|payload| {
                            // For CBOR, we have to put the status code in front.
                            // If we get here, it was successful, so we add:
                            let mut status_with_payload = vec![0]; // Status code: Ok
                            status_with_payload.extend_from_slice(&payload);
                            status_with_payload
                        })
                }
                HidCommand::Cancel
                | HidCommand::Lock
                | HidCommand::Sync
                | HidCommand::KeepAlive
                | HidCommand::Error => unimplemented!(),
            }
        }) {
            Ok(payload) => {
                assert!(self.response.is_none());
                response.payload = payload;
                self.response = Some(response);
                Ok(())
            }
            Err(ctaphid::error::Error::CommandError(ctaphid::error::CommandError::CborError(
                value,
            ))) => match crate::proto::CtapError::try_from_primitive(value) {
                Ok(_) => {
                    // If we have a known Error status code, we return `Ok(())`
                    // (because the transmission was successful, but the operation was not)
                    // and let the code above us handle the error accordingly
                    // on a subsequent recv-call
                    let status_with_payload = vec![value]; // Status code: Err
                    response.payload = status_with_payload; // No additional payload
                    self.response = Some(response);
                    Ok(())
                }
                Err(_) => panic!("Failed to parse CtapError from {value}"),
            },
            Err(err) => panic!("failed to execute CTAP2 command: {err:?}"),
        }
    }

    pub fn virt_recv(&mut self) -> Result<HidMessage, Error> {
        assert!(self.response.is_some());
        Ok(self.response.take().unwrap())
    }
}
