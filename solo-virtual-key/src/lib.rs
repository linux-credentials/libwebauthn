use std::fmt::Display;
use std::path::Path;
use std::process::Stdio;
use std::thread::sleep;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::spawn;

use log::{debug, warn};

#[allow(dead_code)]
#[derive(Debug)]
pub struct SoloVirtualKey {
    handle: Child,
}

impl Display for SoloVirtualKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SoloVirtualKey(pid={})", self.handle.id().unwrap_or(0))
    }
}

impl Default for SoloVirtualKey {
    fn default() -> Self {
        let key_path = env!("OUT_DIR");
        let binary = Path::new(key_path).join("solokey");
        if !binary.exists() {
            panic!("Binary not found at path {:?}", binary);
        }

        let mut handle = Command::new(binary)
            .args(&["-b", "udp"])
            .current_dir(key_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("failed to start virtual key");
        debug!("Started virtual key process: {:?}", handle);

        let mut stdout = BufReader::new(handle.stdout.take().unwrap()).lines();
        let mut stderr = BufReader::new(handle.stderr.take().unwrap()).lines();

        spawn(async move {
            while let Ok(Some(line)) = stderr.next_line().await {
                warn!("stderr: {}", line);
            }
        });

        spawn(async move {
            while let Ok(Some(line)) = stdout.next_line().await {
                debug!("stdout: {}", line);
            }
        });

        sleep(Duration::from_millis(50));
        Self { handle }
    }
}
