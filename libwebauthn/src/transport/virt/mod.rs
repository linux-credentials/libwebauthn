mod device;
mod pipe;

use super::hid::framing::HidCommand;
use super::hid::framing::HidMessage;
use crate::webauthn::Error;
use num_enum::TryFromPrimitive;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::thread::JoinHandle;

#[derive(Debug)]
pub(crate) struct VirtHidDevice {
    req_tx: Sender<HidMessage>,
    resp_rx: Receiver<HidMessage>,
    _device_thread: JoinHandle<()>,
}

impl Drop for VirtHidDevice {
    fn drop(&mut self) {
        // Telling the thread to quit
        let _ = self
            .req_tx
            .send(HidMessage::new(0, HidCommand::Cancel, &[]));
    }
}

impl VirtHidDevice {
    pub fn new() -> Self {
        let (req_tx, req_rx) = std::sync::mpsc::channel::<HidMessage>();
        let (resp_tx, resp_rx) = std::sync::mpsc::channel::<HidMessage>();

        // Due to the callback-structure of trussed, we simply can't call
        // device::run_ctaphid() multiple times, as that would mean a new
        // device initialization for each call (and rendering every shared
        // secret invalid).
        // So we let it run only once, but in a seperate thread, and simply
        // pass messages back and forth.
        // This way, the device works across multiple request calls,
        // as long as the device-object lives. Everything is wiped on dropping
        // the device object.
        let thread_handle = thread::spawn(move || {
            device::run_ctaphid(move |device| {
                while let Ok(msg) = req_rx.recv() {
                    let resp = match msg.cmd {
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
                        HidCommand::Cancel => break,
                        HidCommand::Lock
                        | HidCommand::Sync
                        | HidCommand::KeepAlive
                        | HidCommand::Error => unimplemented!(),
                    };
                    match resp {
                        Ok(payload) => {
                            let mut response = msg.clone();
                            response.payload = payload;
                            match resp_tx.send(response) {
                                Ok(_) => continue,
                                Err(_) => break,
                            }
                        }
                        Err(ctaphid::error::Error::CommandError(
                            ctaphid::error::CommandError::CborError(value),
                        )) => match crate::proto::CtapError::try_from_primitive(value) {
                            Ok(_) => {
                                // If we have a known Error status code, we return `Ok(())`
                                // (because the transmission was successful, but the operation was not)
                                // and let the code above us handle the error accordingly
                                // on a subsequent recv-call
                                let mut response = msg.clone();
                                let status_with_payload = vec![value]; // Status code: Err
                                response.payload = status_with_payload; // No additional payload
                                match resp_tx.send(response) {
                                    Ok(_) => continue,
                                    Err(_) => break,
                                }
                            }
                            Err(_) => panic!("Failed to parse CtapError from {value}"),
                        },
                        Err(err) => panic!("failed to execute CTAP2 command: {err:?}"),
                    }
                }
            })
        });
        Self {
            _device_thread: thread_handle,
            req_tx,
            resp_rx,
        }
    }

    pub fn virt_send(&mut self, msg: &HidMessage) -> Result<(), Error> {
        let _ = self.req_tx.send(msg.to_owned());
        Ok(())
    }

    pub fn virt_recv(&mut self) -> Result<HidMessage, Error> {
        let response = self.resp_rx.recv().unwrap();
        Ok(response)
    }
}
