// Extracted (and slightly modified) from the fido-authenticator crate:
//   https://github.com/Nitrokey/fido-authenticator/blob/main/tests/virt/mod.rs
//
// License: Apache-2.0 or MIT
//
// Authors:
// - Robin Krahl <robin@nitrokey.com>

use super::pipe::Pipe;
use std::{
    borrow::Cow,
    cell::RefCell,
    fmt::{self, Debug, Formatter},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, SystemTime},
};

use ctaphid::{
    error::{RequestError, ResponseError},
    HidDevice, HidDeviceInfo,
};
use ctaphid_dispatch::{Channel, Dispatch, Requester, DEFAULT_MESSAGE_SIZE};
use fido_authenticator::{Authenticator, Config, Conforming};
use littlefs2::{object_safe::DynFilesystem, path, path::PathBuf};
use rand::{
    distributions::{Distribution, Uniform},
    RngCore as _,
};
use tracing::info;
use trussed::{
    backend::BackendId,
    platform::Platform as _,
    store::Store as _,
    virt::{self, StorageConfig, StoreConfig},
};
use trussed_staging::virt::{BackendIds, Client, Dispatcher};

// see: https://github.com/Nitrokey/nitrokey-3-firmware/tree/main/utils/test-certificates/fido
const ATTESTATION_CERT: &[u8] = include_bytes!("../../../../data/fido-cert.der");
const ATTESTATION_KEY: &[u8] = include_bytes!("../../../../data/fido-key.trussed");

pub fn run_ctaphid<F, T>(storage_dir: &Path, f: F) -> T
where
    F: FnOnce(ctaphid::Device<Device>) -> T + Send,
    T: Send,
{
    run_ctaphid_with_options(storage_dir, Default::default(), f)
}

pub fn run_ctaphid_with_options<F, T>(storage_dir: &Path, options: Options, f: F) -> T
where
    F: FnOnce(ctaphid::Device<Device>) -> T + Send,
    T: Send,
{
    let mut files = options.files;
    files.push((path!("fido/x5c/00").into(), ATTESTATION_CERT.into()));
    files.push((path!("fido/sec/00").into(), ATTESTATION_KEY.into()));
    with_client(
        storage_dir,
        &files,
        |client| {
            let mut authenticator = Authenticator::new(
                client,
                Conforming {},
                Config {
                    max_msg_size: 0,
                    skip_up_timeout: None,
                    max_resident_credential_count: options.max_resident_credential_count,
                    large_blobs: None,
                    nfc_transport: false,
                },
            );

            let channel = Channel::new();
            let (rq, rp) = channel.split().unwrap();

            thread::scope(|s| {
                let stop = Arc::new(AtomicBool::new(false));
                let poller_stop = stop.clone();
                let poller = s.spawn(move || {
                    let mut dispatch = Dispatch::new(rp);
                    while !poller_stop.load(Ordering::Relaxed) {
                        dispatch.poll(&mut [&mut authenticator]);
                        thread::sleep(Duration::from_millis(1));
                    }
                });

                let runner = s.spawn(move || {
                    let device = Device::new(rq);
                    let device = ctaphid::Device::new(device, DeviceInfo).unwrap();
                    f(device)
                });

                let result = runner.join();
                stop.store(true, Ordering::Relaxed);
                poller.join().unwrap();
                result.unwrap()
            })
        },
        |ifs| {
            if let Some(inspect_ifs) = options.inspect_ifs {
                inspect_ifs(ifs);
            }
        },
    )
}

pub type InspectFsFn = Box<dyn Fn(&dyn DynFilesystem)>;

#[derive(Default)]
pub struct Options {
    pub files: Vec<(PathBuf, Vec<u8>)>,
    pub max_resident_credential_count: Option<u32>,
    pub inspect_ifs: Option<InspectFsFn>,
}

#[derive(PartialEq)]
pub struct Ctap2Error(pub u8);

impl Debug for Ctap2Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ctap2Error")
            .field(&format_args!("{:#x}", self.0))
            .finish()
    }
}

#[derive(Debug)]
pub struct DeviceInfo;

impl HidDeviceInfo for DeviceInfo {
    fn vendor_id(&self) -> u16 {
        0x20a0
    }

    fn product_id(&self) -> u16 {
        0x42b2
    }

    fn path(&self) -> Cow<'_, str> {
        "test".into()
    }
}

pub struct Device<'a>(RefCell<Pipe<'a, DEFAULT_MESSAGE_SIZE>>);

impl<'a> Device<'a> {
    fn new(requester: Requester<'a, DEFAULT_MESSAGE_SIZE>) -> Self {
        Self(RefCell::new(Pipe::new(requester)))
    }
}

impl HidDevice for Device<'_> {
    type Info = DeviceInfo;

    fn send(&self, data: &[u8]) -> Result<(), RequestError> {
        self.0.borrow_mut().push(data);
        Ok(())
    }

    fn receive<'a>(
        &self,
        buffer: &'a mut [u8],
        timeout: Option<Duration>,
    ) -> Result<&'a [u8], ResponseError> {
        let start = SystemTime::now();

        loop {
            if let Some(timeout) = timeout {
                let elapsed = start.elapsed().unwrap();
                if elapsed >= timeout {
                    return Err(ResponseError::Timeout);
                }
            }

            if let Some(response) = self.0.borrow_mut().pop() {
                return if buffer.len() >= response.len() {
                    info!("received response: {} bytes", response.len());
                    buffer[..response.len()].copy_from_slice(&response);
                    Ok(&buffer[..response.len()])
                } else {
                    Err(ResponseError::PacketReceivingFailed(
                        "invalid buffer size".into(),
                    ))
                };
            }

            thread::sleep(Duration::from_millis(1));
        }
    }
}

fn with_client<F, F2, T>(
    storage_dir: &Path,
    files: &[(PathBuf, Vec<u8>)],
    f: F,
    inspect_ifs: F2,
) -> T
where
    F: FnOnce(Client) -> T,
    F2: FnOnce(&dyn DynFilesystem),
{
    let store = StoreConfig {
        internal: StorageConfig::filesystem(storage_dir.join("internal")),
        external: StorageConfig::filesystem(storage_dir.join("external")),
        volatile: StorageConfig::filesystem(storage_dir.join("volatile")),
    };
    // Since we want to run this repeatedly, RAM-storage sadly doesn't work,
    // as it is wiped with each `with_platform()`-call. So we have to switch
    // to using filesystem-storage
    // virt::with_platform(StoreConfig::ram(), |mut platform| {
    virt::with_platform(store, |mut platform| {
        // virt always uses the same seed -- request some random bytes to reach a somewhat random
        // state
        let uniform = Uniform::from(0..64);
        let n = uniform.sample(&mut rand::thread_rng());
        for _ in 0..n {
            platform.rng().next_u32();
        }

        let store = platform.store();
        let ifs = store.ifs();

        for (path, content) in files {
            if let Some(dir) = path.parent() {
                ifs.create_dir_all(&dir).unwrap();
            }
            ifs.write(path, content).unwrap();
        }

        let result = platform.run_client_with_backends(
            "fido",
            Dispatcher::default(),
            &[
                BackendId::Custom(BackendIds::StagingBackend),
                BackendId::Core,
            ],
            f,
        );

        inspect_ifs(ifs);

        result
    })
}
