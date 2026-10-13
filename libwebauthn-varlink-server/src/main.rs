//! Server binary: Binds the zlink
//! service to a Unix domain socket whose path is given as the first CLI
//! argument.
mod provider;
mod service;
#[cfg(test)]
mod tests;

use std::env;
use std::os::unix::fs::FileTypeExt;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use libwebauthn::ops::webauthn::SystemPublicSuffixList;
use tracing_subscriber::EnvFilter;
use zlink::{tokio::unix, Server};

use crate::provider::CableProvider;
use crate::service::WebauthnService;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .without_time()
        .init();

    let Some(socket_path) = env::args_os().nth(1) else {
        eprintln!("usage: webauthd-link <socket-path>");
        return ExitCode::FAILURE;
    };
    let socket_path = PathBuf::from(socket_path);

    let psl = match SystemPublicSuffixList::auto() {
        Ok(psl) => psl,
        Err(err) => {
            eprintln!("failed to load the public suffix list: {err}");
            return ExitCode::FAILURE;
        }
    };

    // Remove a stale socket left by a previous run, but never anything else:
    // a mistyped path must not delete an unrelated file.
    if let Ok(metadata) = std::fs::symlink_metadata(&socket_path) {
        if !metadata.file_type().is_socket() {
            eprintln!("{} exists and is not a socket", socket_path.display());
            return ExitCode::FAILURE;
        }
        let _ = std::fs::remove_file(&socket_path);
    }
    let listener = match unix::bind(&socket_path) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("failed to bind {}: {err}", socket_path.display());
            return ExitCode::FAILURE;
        }
    };

    let service = WebauthnService::new(Arc::new(psl), Arc::new(CableProvider));
    if let Err(err) = Server::new(listener, service).run().await {
        eprintln!("server error: {err}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
