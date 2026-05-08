mod device;
mod pipe;

use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::thread::JoinHandle;

use libwebauthn::proto::CtapError;
use libwebauthn::transport::hid::framing::{HidCommand, HidMessage};
use libwebauthn::transport::hid::{virtual_device, HidDevice, HidPipeBackend};
use num_enum::TryFromPrimitive;

/// `HidPipeBackend` implementation backed by an in-process trussed-staging
/// fido-authenticator. Each instance owns a worker thread that owns the
/// trussed client; messages are exchanged over `mpsc` channels.
#[derive(Debug)]
pub struct TrussedVirtBackend {
    req_tx: Sender<HidMessage>,
    resp_rx: Receiver<HidMessage>,
    _worker: JoinHandle<()>,
}

impl TrussedVirtBackend {
    pub fn new() -> Self {
        let (req_tx, req_rx) = std::sync::mpsc::channel::<HidMessage>();
        let (resp_tx, resp_rx) = std::sync::mpsc::channel::<HidMessage>();

        // Due to the callback-structure of trussed, we simply can't call
        // device::run_ctaphid() multiple times, as that would mean a new
        // device initialization for each call (and rendering every shared
        // secret invalid).
        // So we let it run only once, but in a separate thread, and simply
        // pass messages back and forth.
        let worker = thread::spawn(move || {
            device::run_ctaphid(move |device| {
                while let Ok(msg) = req_rx.recv() {
                    let resp = match msg.cmd {
                        HidCommand::Ping => device.ping(&msg.payload).map(|_| Vec::new()),
                        HidCommand::Msg => device.ctap1(&msg.payload),
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
                        HidCommand::Cbor => device
                            .ctap2(msg.payload[0], &msg.payload[1..])
                            .map(|payload| {
                                // For CBOR, status code goes in front; success = 0.
                                let mut status_with_payload = vec![0];
                                status_with_payload.extend_from_slice(&payload);
                                status_with_payload
                            }),
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
                            if resp_tx.send(response).is_err() {
                                break;
                            }
                        }
                        Err(ctaphid::error::Error::CommandError(
                            ctaphid::error::CommandError::CborError(value),
                        )) => match CtapError::try_from_primitive(value) {
                            Ok(_) => {
                                // Known CTAP error code: forward as a successful
                                // transmission with the status byte as payload.
                                let mut response = msg.clone();
                                response.payload = vec![value];
                                if resp_tx.send(response).is_err() {
                                    break;
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
            req_tx,
            resp_rx,
            _worker: worker,
        }
    }
}

impl Default for TrussedVirtBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TrussedVirtBackend {
    fn drop(&mut self) {
        // Tell the worker thread to exit cleanly.
        let _ = self
            .req_tx
            .send(HidMessage::new(0, HidCommand::Cancel, &[]));
    }
}

impl HidPipeBackend for TrussedVirtBackend {
    fn send(&mut self, msg: &HidMessage) {
        let _ = self.req_tx.send(msg.to_owned());
    }

    fn recv(&mut self) -> HidMessage {
        self.resp_rx.recv().expect("virt worker disconnected")
    }
}

/// Convenience constructor matching the previous `get_virtual_device()` helper.
pub fn get_virtual_device() -> HidDevice {
    virtual_device(TrussedVirtBackend::new())
}
