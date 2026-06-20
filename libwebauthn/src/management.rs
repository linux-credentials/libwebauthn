//! Administration interfaces for CTAP2 authenticators. This module exposes
//! traits for managing device configuration, biometric enrollment, and stored
//! credentials over any [`Channel`](crate::transport::Channel) transport. These
//! operations require user verification through a PIN or biometric factor, and
//! the protocol handles token acquisition and retry internally.
//!
//! Use [`CredentialManagement`] to enumerate and delete resident credentials,
//! [`AuthenticatorConfig`] to adjust device settings such as PIN policy and
//! enterprise attestation, [`BioEnrollment`] to manage biometric templates, and
//! [`AuthenticatorReset`] to restore an authenticator to factory defaults.
//! Each trait is blanket-implemented for any
//! [`Channel`](crate::transport::Channel), so the same API works across every
//! transport.

mod bio_enrollment;
pub use bio_enrollment::BioEnrollment;

mod authenticator_config;
pub use authenticator_config::AuthenticatorConfig;

mod authenticator_reset;
pub use authenticator_reset::AuthenticatorReset;

mod credential_management;
pub use credential_management::CredentialManagement;
