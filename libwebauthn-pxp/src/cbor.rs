//! PXP's own CBOR messages (QR data, advert suffix, post-handshake and update
//! messages). CTAP payloads are never decoded here.
pub(crate) use serde_cbor_2::{from_slice, to_vec, Value};
