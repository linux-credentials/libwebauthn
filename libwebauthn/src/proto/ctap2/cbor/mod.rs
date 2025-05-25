mod request;
mod response;
mod serde;

pub use request::CborRequest;
pub use response::CborResponse;
pub(crate) use serde::{CborDeserialize, CborError, CborSerialize};
