use std::fmt::Display;

use crate::{fido::FidoRevision, UxUpdate};
use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::transport::ble::btleplug::manager::SupportedRevisions;
use crate::transport::error::Error;

use super::{Channel, Transport};

#[async_trait]
pub trait Device<'d, T, C>: Send + Display
where
    T: Transport,
    C: Channel + 'd,
{
    async fn channel(&'d mut self) -> Result<(C, mpsc::Receiver<UxUpdate>), Error>;
    // async fn supported_protocols(&mut self) -> Result<SupportedProtocols, Error>;
}

#[derive(Debug, Copy, Clone, Default)]
pub struct SupportedProtocols {
    pub u2f: bool, // Can be split into U2F revisions, if needed.
    pub fido2: bool,
}

impl SupportedProtocols {
    pub fn u2f_only() -> Self {
        Self {
            u2f: true,
            ..SupportedProtocols::default()
        }
    }

    pub fn fido2_only() -> Self {
        Self {
            fido2: true,
            ..SupportedProtocols::default()
        }
    }
}

impl From<SupportedRevisions> for SupportedProtocols {
    fn from(revs: SupportedRevisions) -> Self {
        Self {
            u2f: revs.u2fv11 || revs.u2fv12,
            fido2: revs.v2,
        }
    }
}

impl From<FidoRevision> for SupportedProtocols {
    fn from(rev: FidoRevision) -> Self {
        match rev {
            FidoRevision::V2 => SupportedProtocols::fido2_only(),
            FidoRevision::U2fv12 => SupportedProtocols::u2f_only(),
            FidoRevision::U2fv11 => SupportedProtocols::u2f_only(),
        }
    }
}
