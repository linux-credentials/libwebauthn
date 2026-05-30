//! Request and response types for WebAuthn registration and authentication
//! ceremonies, alongside the legacy FIDO U2F operation types. The main types are
//! [`MakeCredentialRequest`](webauthn::MakeCredentialRequest) and
//! [`GetAssertionRequest`](webauthn::GetAssertionRequest), which describe the
//! parameters for creating and asserting a credential, and the matching
//! [`MakeCredentialResponse`](webauthn::MakeCredentialResponse) and
//! [`GetAssertionResponse`](webauthn::GetAssertionResponse) that carry the
//! outcome. The request types also cover WebAuthn extensions such as PRF,
//! HMAC secret, credProtect, and large blob storage.
//!
//! Always build these requests from their WebAuthn IDL JSON with
//! [`MakeCredentialRequest::prepare`](webauthn::MakeCredentialRequest::prepare)
//! and [`GetAssertionRequest::prepare`](webauthn::GetAssertionRequest::prepare):
//! `prepare` validates the caller origin against the relying party ID, so it is
//! the only safe way to construct an operation.
//!
//! The module also defines the operation kinds and user verification
//! requirements, client data hashing helpers, and conversions between the
//! WebAuthn IDL (JSON) representation and the internal types. A U2F response can
//! be promoted to its WebAuthn equivalent through the
//! [`UpgradableResponse`](u2f::UpgradableResponse) trait, which bridges legacy
//! credentials into the WebAuthn world.

pub mod u2f;
pub mod webauthn;
