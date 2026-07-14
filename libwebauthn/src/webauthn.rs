//! High-level FIDO2 (CTAP2) client API for WebAuthn ceremonies. The [`WebAuthn`]
//! trait is blanket-implemented for any [`Channel`]. Its
//! [`webauthn_make_credential`](WebAuthn::webauthn_make_credential) and
//! [`webauthn_get_assertion`](WebAuthn::webauthn_get_assertion) methods run the
//! full CTAP2 make-credential and get-assertion ceremonies, including the user
//! verification flow, PIN and biometric token handling, credential filtering via
//! preflight, and extension support. When a device does not support FIDO2, the
//! ceremony falls back to U2F (CTAP1).
//!
//! User verification is handled internally by the [`pin_uv_auth_token`] module,
//! which manages PIN and biometric UV, reuse of a cached pinUvAuthToken, shared
//! secret establishment, and the fallback from biometric to PIN. Failures are
//! reported as [`WebAuthnError`], which distinguishes CTAP protocol errors
//! ([`CtapError`]), transport errors, and platform errors.

pub mod error;
pub mod pin_uv_auth_token;

use async_trait::async_trait;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::fido::FidoProtocol;
use crate::ops::u2f::{RegisterRequest, SignRequest, UpgradableResponse};
use crate::ops::webauthn::{
    decrypt_first_matching, delete_authenticator_large_blob, fetch_large_blob_entries,
    max_fragment_length, write_authenticator_large_blob, DowngradableRequest,
    GetAssertionLargeBlobExtension, GetAssertionLargeBlobExtensionOutput, GetAssertionRequest,
    GetAssertionResponse, GetAssertionResponseUnsignedExtensions, UserVerificationRequirement,
};
use crate::ops::webauthn::{MakeCredentialRequest, MakeCredentialResponse};
use crate::proto::ctap1::Ctap1;
use crate::proto::ctap2::cbor::CborRequest;
use crate::proto::ctap2::preflight::{ctap2_preflight, ctap2_preflight_with_appid};
use crate::proto::ctap2::{
    Ctap2, Ctap2ClientPinRequest, Ctap2GetAssertionRequest, Ctap2GetAssertionResponse,
    Ctap2GetInfoResponse, Ctap2MakeCredentialRequest, Ctap2PublicKeyCredentialDescriptor,
    Ctap2UserVerificationOperation,
};
use crate::transport::{AuthTokenData, Channel};
pub use crate::webauthn::error::{CtapError, PlatformError, WebAuthnError};
use crate::UvUpdate;

use pin_uv_auth_token::{user_verification, UsedPinUvAuthToken};

// See W3C webauthn#2337.
fn prf_forces_uv_upgrade(prf_present: bool, uv: UserVerificationRequirement) -> bool {
    prf_present && !uv.is_required()
}

/// Drop credential ids longer than maxCredentialIdLength, which cannot belong to this device.
fn filter_oversized_credentials(
    info: &Ctap2GetInfoResponse,
    credentials: &mut Vec<Ctap2PublicKeyCredentialDescriptor>,
) {
    if let Some(max_len) = info.max_credential_id_length() {
        credentials.retain(|credential| credential.id.len() <= max_len);
    }
}

fn ensure_credential_count(count: usize, info: &Ctap2GetInfoResponse) -> Result<(), PlatformError> {
    if let Some(max) = info.max_credential_count_in_list() {
        if count > max {
            warn!(
                count,
                max, "credential list exceeds maxCredentialCountInList"
            );
            return Err(PlatformError::RequestTooLarge);
        }
    }
    Ok(())
}

fn ensure_msg_size(
    request: &CborRequest,
    info: &Ctap2GetInfoResponse,
) -> Result<(), PlatformError> {
    let size = request.ctap_hid_data().len();
    let max = info.max_msg_size();
    if size > max {
        warn!(size, max, "serialized request exceeds maxMsgSize");
        return Err(PlatformError::RequestTooLarge);
    }
    Ok(())
}

fn enforce_get_assertion_limits(
    request: &Ctap2GetAssertionRequest,
    info: &Ctap2GetInfoResponse,
) -> Result<(), PlatformError> {
    ensure_credential_count(request.allow.len(), info)?;
    ensure_msg_size(&request.try_into()?, info)
}

fn enforce_make_credential_limits(
    request: &Ctap2MakeCredentialRequest,
    info: &Ctap2GetInfoResponse,
) -> Result<(), PlatformError> {
    let exclude_count = request.exclude.as_ref().map_or(0, Vec::len);
    ensure_credential_count(exclude_count, info)?;
    ensure_msg_size(&request.try_into()?, info)
}

macro_rules! handle_errors {
    // Callers that never reuse a persistent token (make-credential, get-assertion,
    // authenticator-config, bio-enrollment): nothing to notify on a persistent rejection.
    ($channel: expr, $resp: expr, $uv_auth_used: expr, $timeout: expr) => {
        handle_errors!(@inner $channel, $resp, $uv_auth_used, $timeout, {})
    };
    // Credential-management callers pass their request so a rejected persistent token is
    // marked on it, forcing the retry to mint a fresh token instead of reusing the same
    // stale record. This keeps loop termination independent of the best-effort store delete.
    ($channel: expr, $resp: expr, $uv_auth_used: expr, $timeout: expr, $request: expr) => {
        handle_errors!(@inner $channel, $resp, $uv_auth_used, $timeout, {
            $request.note_persistent_token_rejected();
        })
    };
    (@inner $channel: expr, $resp: expr, $uv_auth_used: expr, $timeout: expr, $on_persistent_reject: block) => {
        match $resp {
            Err(WebAuthnError::Ctap(CtapError::PINAuthInvalid))
                if $uv_auth_used == UsedPinUvAuthToken::FromEphemeralStorage =>
            {
                info!("PINAuthInvalid: Clearing auth token storage and trying again.");
                $channel.clear_uv_auth_token_store();
                continue;
            }
            Err(WebAuthnError::Ctap(CtapError::PINAuthInvalid))
                if matches!($uv_auth_used, UsedPinUvAuthToken::FromPersistentStorage(_)) =>
            {
                info!("PINAuthInvalid on a persistent token: evicting the record and retrying.");
                if let UsedPinUvAuthToken::FromPersistentStorage(id) = &$uv_auth_used {
                    if let Some(store) = $channel.persistent_token_store() {
                        store.delete(id).await;
                    }
                }
                $on_persistent_reject
                continue;
            }
            Err(WebAuthnError::Ctap(CtapError::UVInvalid)) => {
                let attempts_left = $channel
                    .ctap2_client_pin(&Ctap2ClientPinRequest::new_get_uv_retries(), $timeout)
                    .await
                    .map(|x| x.uv_retries)
                    .ok() // It's optional, so soft-error here
                    .flatten();
                $channel
                    .send_ux_update(UvUpdate::UvRetry { attempts_left }.into())
                    .await;
                break Err(WebAuthnError::Ctap(CtapError::UVInvalid));
            }
            x => {
                break x;
            }
        }
    };
}
pub(crate) use handle_errors;

#[async_trait]
pub trait WebAuthn: Channel {
    async fn webauthn_make_credential(
        &mut self,
        op: &MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, WebAuthnError<Self::TransportError>>;
    async fn webauthn_get_assertion(
        &mut self,
        op: &GetAssertionRequest,
    ) -> Result<GetAssertionResponse, WebAuthnError<Self::TransportError>>;
}

#[async_trait]
impl<C> WebAuthn for C
where
    C: Channel,
{
    #[instrument(skip_all, fields(dev = % self))]
    async fn webauthn_make_credential(
        &mut self,
        op: &MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, WebAuthnError<C::TransportError>> {
        let upgraded;
        let prf_present = op.extensions.as_ref().is_some_and(|e| e.prf.is_some());
        let op = if prf_forces_uv_upgrade(prf_present, op.user_verification) {
            debug!("PRF requested: forcing userVerification=required (W3C webauthn#2337)");
            upgraded = MakeCredentialRequest {
                user_verification: UserVerificationRequirement::Required,
                ..op.clone()
            };
            &upgraded
        } else {
            op
        };
        trace!(?op, "WebAuthn MakeCredential request");
        let protocol = negotiate_protocol(self, op.is_downgradable()).await?;
        let mut response = match protocol {
            FidoProtocol::FIDO2 => make_credential_fido2(self, op).await,
            FidoProtocol::U2F => make_credential_u2f(self, op).await,
        }?;
        response.transport = Some(self.transport());
        Ok(response)
    }

    #[instrument(skip_all, fields(dev = % self))]
    async fn webauthn_get_assertion(
        &mut self,
        op: &GetAssertionRequest,
    ) -> Result<GetAssertionResponse, WebAuthnError<C::TransportError>> {
        let upgraded;
        let prf_present = op.extensions.as_ref().is_some_and(|e| e.prf.is_some());
        let op = if prf_forces_uv_upgrade(prf_present, op.user_verification) {
            debug!("PRF requested: forcing userVerification=required (W3C webauthn#2337)");
            upgraded = GetAssertionRequest {
                user_verification: UserVerificationRequirement::Required,
                ..op.clone()
            };
            &upgraded
        } else {
            op
        };
        trace!(?op, "WebAuthn GetAssertion request");
        let protocol = negotiate_protocol(self, op.is_downgradable()).await?;
        let mut response = match protocol {
            FidoProtocol::FIDO2 => get_assertion_fido2(self, op).await,
            FidoProtocol::U2F => get_assertion_u2f(self, op).await,
        }?;
        let transport = self.transport();
        for assertion in &mut response.assertions {
            assertion.transport = Some(transport);
        }
        Ok(response)
    }
}

async fn make_credential_fido2<C: Channel>(
    channel: &mut C,
    op: &MakeCredentialRequest,
) -> Result<MakeCredentialResponse, WebAuthnError<C::TransportError>> {
    let get_info_response = channel.ctap2_get_info().await?;
    let mut ctap2_request =
        Ctap2MakeCredentialRequest::from_webauthn_request(op, &get_info_response)?;
    if let Some(exclude) = ctap2_request.exclude.as_mut() {
        filter_oversized_credentials(&get_info_response, exclude);
    }
    if C::supports_preflight() {
        if let Some(exclude_list) = ctap2_request.exclude.clone() {
            // FIDO AppID Exclusion (WebAuthn L3 §10.1.2): if the relying
            // party supplied a legacy AppID, the preflight must test
            // each excludeList entry against both `SHA-256(rp.id)` and
            // `SHA-256(appidExclude)` so that legacy U2F-keyed
            // credentials are correctly detected.
            let appid_exclude = op
                .extensions
                .as_ref()
                .and_then(|e| e.appid_exclude.as_deref());
            let filtered_exclude_list = ctap2_preflight_with_appid(
                channel,
                &exclude_list,
                &op.client_data_hash(),
                &op.relying_party.id,
                appid_exclude,
            )
            .await?;
            ctap2_request.exclude = Some(filtered_exclude_list);
        }
    }
    enforce_make_credential_limits(&ctap2_request, &get_info_response)?;
    let response = loop {
        let uv_auth_used = user_verification(
            channel,
            op.user_verification,
            &mut ctap2_request,
            op.timeout,
        )
        .await?;

        // Encrypt hmac-secret-mc before PresenceRequired (mirrors GA below).
        if let Some(auth_data) = channel.get_auth_data() {
            if let Some(ext) = ctap2_request.extensions.as_mut() {
                ext.calculate_hmac_secret_mc(auth_data)?;
            }
        }

        // We've already sent out this update, in case we used builtin UV
        // but in all other cases, we need to touch the device now.
        if uv_auth_used
            != UsedPinUvAuthToken::NewlyCalculated(
                Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingUvWithPermissions,
            )
        {
            channel
                .send_ux_update(UvUpdate::PresenceRequired.into())
                .await;
        }
        handle_errors!(
            channel,
            channel
                .ctap2_make_credential(&ctap2_request, op.timeout)
                .await,
            uv_auth_used,
            op.timeout
        )
    }?;
    let make_cred =
        response.into_make_credential_output(op, Some(&get_info_response), channel.get_auth_data());
    Ok(make_cred)
}

async fn make_credential_u2f<C: Channel>(
    channel: &mut C,
    op: &MakeCredentialRequest,
) -> Result<MakeCredentialResponse, WebAuthnError<C::TransportError>> {
    let register_request: RegisterRequest = op.try_downgrade()?;

    channel
        .ctap1_register(&register_request)
        .await?
        .try_upgrade(op)
}

async fn get_assertion_fido2<C: Channel>(
    channel: &mut C,
    op: &GetAssertionRequest,
) -> Result<GetAssertionResponse, WebAuthnError<C::TransportError>> {
    // WebAuthn L3 §10.1.5: largeBlob.write/delete requires exactly one allowCredentials entry.
    let large_blob_ext = op.extensions.as_ref().and_then(|e| e.large_blob.as_ref());
    if matches!(
        large_blob_ext,
        Some(GetAssertionLargeBlobExtension::Write(_))
            | Some(GetAssertionLargeBlobExtension::Delete)
    ) && op.allow.len() != 1
    {
        warn!(
            count = op.allow.len(),
            "largeBlob.write/delete requires exactly one allowCredentials entry"
        );
        return Err(WebAuthnError::Platform(PlatformError::NotSupported));
    }

    let get_info_response = channel.ctap2_get_info().await?;
    let mut ctap2_request =
        Ctap2GetAssertionRequest::from_webauthn_request(op, &get_info_response)?;
    filter_oversized_credentials(&get_info_response, &mut ctap2_request.allow);

    if C::supports_preflight() {
        let filtered_allow_list = ctap2_preflight(
            channel,
            &ctap2_request.allow,
            &op.client_data_hash(),
            &op.relying_party_id,
        )
        .await?;
        if filtered_allow_list.is_empty() && !op.allow.is_empty() {
            // We filtered out everything in preflight, meaning none of the allowed
            // credentials are present on this device. So we error out here
            // But the spec requires some form of user interaction, so we run a
            // dummy request, ignore the result and error out.
            warn!("Preflight removed all credentials from the allow-list. Sending dummy request and erroring out.");
            let dummy_request: Ctap2MakeCredentialRequest = Ctap2MakeCredentialRequest::dummy();
            channel
                .send_ux_update(UvUpdate::PresenceRequired.into())
                .await;
            let _ = channel
                .ctap2_make_credential(&dummy_request, op.timeout)
                .await;
            return Err(WebAuthnError::Ctap(CtapError::NoCredentials));
        }
        ctap2_request.allow = filtered_allow_list;
    } else if ctap2_request.allow.is_empty() && !op.allow.is_empty() {
        // No preflight (cable): all entries were oversized, so don't fall through to an empty allowList.
        return Err(WebAuthnError::Ctap(CtapError::NoCredentials));
    }

    enforce_get_assertion_limits(&ctap2_request, &get_info_response)?;

    let response = loop {
        let uv_auth_used = user_verification(
            channel,
            op.user_verification,
            &mut ctap2_request,
            op.timeout,
        )
        .await?;
        // Order is important here!
        // We can error out in calculate_hmac() with PlatformError's,
        // so only send out the UvUpdate after we are done with hmac.
        if let Some(auth_data) = channel.get_auth_data() {
            if let Some(e) = ctap2_request.extensions.as_mut() {
                e.calculate_hmac(&op.allow, auth_data)?;
            }
        }

        // We've already sent out this update, in case we used builtin UV
        // but in all other cases, we need to touch the device now.
        if uv_auth_used
            != UsedPinUvAuthToken::NewlyCalculated(
                Ctap2UserVerificationOperation::GetPinUvAuthTokenUsingUvWithPermissions,
            )
        {
            channel
                .send_ux_update(UvUpdate::PresenceRequired.into())
                .await;
        }

        handle_errors!(
            channel,
            channel
                .ctap2_get_assertion(&ctap2_request, op.timeout)
                .await,
            uv_auth_used,
            op.timeout
        )
    }?;
    let expected_rp_id_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::default();
        hasher.update(op.relying_party_id.as_bytes());
        hasher.finalize()
    };
    let validate_rp_id_hash =
        |resp: &Ctap2GetAssertionResponse| -> Result<(), WebAuthnError<C::TransportError>> {
            if resp.authenticator_data.rp_id_hash.as_slice() != expected_rp_id_hash.as_slice() {
                warn!("getAssertion rpIdHash does not match the requested RP ID");
                return Err(WebAuthnError::Platform(
                    PlatformError::InvalidDeviceResponse,
                ));
            }
            Ok(())
        };

    validate_rp_id_hash(&response)?;
    // Cap iteration so a hostile numberOfCredentials cannot force an unbounded loop.
    let max_count = get_info_response
        .max_credential_count_in_list()
        .unwrap_or(255);
    let count = (response.credentials_count.unwrap_or(1) as usize).min(max_count);
    let mut ctap_responses = vec![response];
    for i in 1..count {
        debug!({ i }, "Fetching additional credential");
        // GetNextAssertion doesn't use PinUVAuthToken, so we don't need to check uv_auth_used here
        let next = channel.ctap2_get_next_assertion(op.timeout).await?;
        validate_rp_id_hash(&next)?;
        ctap_responses.push(next);
    }

    // largeBlob extension (WebAuthn L3 §10.1.5):
    //   Read   → authenticatorLargeBlobs(get): decrypt and surface the per-credential blob.
    //   Write  → authenticatorLargeBlobs(get+set): RMW + chunked upload of the updated array.
    //   Delete → same as Write but with the entry erased (no new entry appended).
    // Failures are non-fatal: per L3, `blob` is absent on read failure and
    // `written` is `false` on write/delete failure. Resolved here before the
    // CTAP responses are converted to Assertion so the largeBlobKey stays
    // within this scope.
    let max_fragment = max_fragment_length(get_info_response.max_msg_size);
    let large_blob_outputs = match large_blob_ext {
        Some(GetAssertionLargeBlobExtension::Read) => {
            // The largeBlobArray is device-wide: fetch and parse once, decrypt per credential.
            let entries = if ctap_responses.iter().any(|r| r.large_blob_key.is_some()) {
                match fetch_large_blob_entries(channel, max_fragment, op.timeout).await {
                    Ok(entries) => Some(entries),
                    Err(e) => {
                        warn!(?e, "authenticatorLargeBlobs(get) failed; no blob returned");
                        None
                    }
                }
            } else {
                None
            };
            ctap_responses
                .iter()
                .map(|resp| {
                    let blob = match (entries.as_ref(), extract_large_blob_key(resp)) {
                        (Some(entries), Some(key)) => {
                            match decrypt_first_matching::<C::TransportError>(entries, &key) {
                                Ok(blob) => blob,
                                Err(e) => {
                                    warn!(?e, "largeBlob decrypt failed; no blob returned");
                                    None
                                }
                            }
                        }
                        _ => None,
                    };
                    GetAssertionLargeBlobExtensionOutput {
                        blob,
                        written: None,
                    }
                })
                .collect::<Vec<_>>()
        }
        Some(GetAssertionLargeBlobExtension::Write(payload)) => {
            // L3 §10.1.5: write applies to the single matched credential. We
            // enforced allow.len()==1 above, and ctap_responses then has
            // exactly one element.
            let auth_data = channel.get_auth_data().cloned();
            let written = match ctap_responses.first() {
                Some(resp) => {
                    write_or_delete_for_first(
                        channel,
                        resp,
                        auth_data,
                        max_fragment,
                        op.timeout,
                        WriteOrDelete::Write(payload.as_slice()),
                    )
                    .await
                }
                None => false,
            };
            let mut outs: Vec<_> = vec![
                GetAssertionLargeBlobExtensionOutput {
                    blob: None,
                    written: Some(written),
                };
                ctap_responses.len()
            ];
            // Only the first (and only) assertion carries the `written` flag.
            for o in outs.iter_mut().skip(1) {
                o.written = None;
            }
            outs
        }
        Some(GetAssertionLargeBlobExtension::Delete) => {
            let auth_data = channel.get_auth_data().cloned();
            let written = match ctap_responses.first() {
                Some(resp) => {
                    write_or_delete_for_first(
                        channel,
                        resp,
                        auth_data,
                        max_fragment,
                        op.timeout,
                        WriteOrDelete::Delete,
                    )
                    .await
                }
                None => false,
            };
            let mut outs: Vec<_> = vec![
                GetAssertionLargeBlobExtensionOutput {
                    blob: None,
                    written: Some(written),
                };
                ctap_responses.len()
            ];
            for o in outs.iter_mut().skip(1) {
                o.written = None;
            }
            outs
        }
        None => Vec::new(),
    };

    let mut assertions: Vec<_> = ctap_responses
        .into_iter()
        .map(|r| r.into_assertion_output(op, channel.get_auth_data()))
        .collect();
    if !large_blob_outputs.is_empty() {
        for (assertion, entry) in assertions.iter_mut().zip(large_blob_outputs) {
            match assertion.unsigned_extensions_output.as_mut() {
                Some(unsigned) => unsigned.large_blob = Some(entry),
                None => {
                    assertion.unsigned_extensions_output =
                        Some(GetAssertionResponseUnsignedExtensions {
                            large_blob: Some(entry),
                            ..Default::default()
                        });
                }
            }
        }
    }

    Ok(assertions.as_slice().into())
}

enum WriteOrDelete<'a> {
    Write(&'a [u8]),
    Delete,
}

fn extract_large_blob_key(resp: &Ctap2GetAssertionResponse) -> Option<[u8; 32]> {
    let buf = resp.large_blob_key.as_ref()?;
    match <[u8; 32]>::try_from(buf.as_slice()) {
        Ok(k) => Some(k),
        Err(_) => {
            warn!(
                len = buf.len(),
                "largeBlobKey has unexpected length (expected 32); skipping"
            );
            None
        }
    }
}

/// Drive `write_authenticator_large_blob` / `delete_authenticator_large_blob` for the single
/// credential of a write/delete assertion. Returns the `written` flag per WebAuthn L3 §10.1.5.
async fn write_or_delete_for_first<C: Channel>(
    channel: &mut C,
    resp: &Ctap2GetAssertionResponse,
    auth_data: Option<AuthTokenData>,
    max_fragment: u32,
    timeout: std::time::Duration,
    op: WriteOrDelete<'_>,
) -> bool {
    let Some(key) = extract_large_blob_key(resp) else {
        warn!("largeBlobKey absent from assertion; cannot write/delete");
        return false;
    };
    // CTAP 2.2 §6.10.2 lines 100-115: the authenticator enforces pinUvAuthParam
    // only if it is UV-protected. On an unprotected authenticator (no clientPin,
    // no built-in UV) user_verification stores no token, so we send the chunks
    // without auth params and let the authenticator's "skip auth block" path run.
    let pin_uv_auth: Option<(&[u8], _)> = auth_data.as_ref().and_then(|d| {
        d.pin_uv_auth_token
            .as_deref()
            .map(|t| (t, d.protocol_version))
    });
    let result = match op {
        WriteOrDelete::Write(payload) => {
            write_authenticator_large_blob(
                channel,
                &key,
                payload,
                max_fragment,
                pin_uv_auth,
                timeout,
            )
            .await
        }
        WriteOrDelete::Delete => {
            delete_authenticator_large_blob(channel, &key, max_fragment, pin_uv_auth, timeout).await
        }
    };
    match result {
        Ok(()) => true,
        Err(e) => {
            warn!(?e, "authenticatorLargeBlobs(set) failed; written=false");
            false
        }
    }
}

async fn get_assertion_u2f<C: Channel>(
    channel: &mut C,
    op: &GetAssertionRequest,
) -> Result<GetAssertionResponse, WebAuthnError<C::TransportError>> {
    use sha2::{Digest, Sha256};

    let sign_requests: Vec<SignRequest> = op.try_downgrade()?;

    // Precompute the AppID-derived application parameter so we can
    // distinguish a match-by-rpId from a match-by-appid for the
    // `clientExtensionResults.appid` output. The downgrade path emits
    // both forms of SignRequest when `appid` is set.
    let appid_hash: Option<Vec<u8>> =
        op.extensions
            .as_ref()
            .and_then(|e| e.appid.as_ref())
            .map(|appid| {
                let mut hasher = Sha256::default();
                hasher.update(appid.as_bytes());
                hasher.finalize().to_vec()
            });

    for sign_request in sign_requests {
        match channel.ctap1_sign(&sign_request).await {
            Ok(response) => {
                debug!("Found successful candidate in allowList");
                let mut upgraded = response.try_upgrade(&sign_request)?;
                // Surface the FIDO AppID extension output in the
                // assertion's clientExtensionResults.
                if let Some(ref appid_hash) = appid_hash {
                    let used_appid = sign_request.app_id_hash == *appid_hash;
                    for assertion in upgraded.assertions.iter_mut() {
                        let unsigned = assertion
                            .unsigned_extensions_output
                            .get_or_insert_with(Default::default);
                        unsigned.appid = Some(used_appid);
                    }
                }
                return Ok(upgraded);
            }
            Err(WebAuthnError::Ctap(CtapError::NoCredentials)) => {
                debug!("No credentials found, trying with the next.");
            }
            Err(err) => {
                error!(
                    ?err,
                    "Unexpected error whilst trying each credential in allowList."
                );
                return Err(err);
            }
        }
    }
    warn!("None of the credentials in the original request's allowList were found.");
    Err(WebAuthnError::Ctap(CtapError::NoCredentials))
}

#[instrument(skip_all)]
async fn negotiate_protocol<C: Channel>(
    channel: &mut C,
    allow_u2f: bool,
) -> Result<FidoProtocol, WebAuthnError<C::TransportError>> {
    let supported = channel.supported_protocols().await?;
    if !supported.u2f && !supported.fido2 {
        return Err(WebAuthnError::Platform(PlatformError::NotSupported));
    }

    if !allow_u2f && !supported.fido2 {
        return Err(WebAuthnError::Platform(PlatformError::NotSupported));
    }

    let fido_protocol = if supported.fido2 {
        FidoProtocol::FIDO2
    } else {
        // Ensure CTAP1 version is reported correctly.
        channel.ctap1_version().await?;
        FidoProtocol::U2F
    };

    if fido_protocol == FidoProtocol::U2F {
        warn!("Negotiated protocol downgrade from FIDO2 to FIDO U2F");
    } else {
        debug!("Selected protocol: {:?}", fido_protocol);
    }
    Ok(fido_protocol)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prf_absent_no_upgrade() {
        assert!(!prf_forces_uv_upgrade(
            false,
            UserVerificationRequirement::Discouraged
        ));
        assert!(!prf_forces_uv_upgrade(
            false,
            UserVerificationRequirement::Preferred
        ));
        assert!(!prf_forces_uv_upgrade(
            false,
            UserVerificationRequirement::Required
        ));
    }

    #[test]
    fn prf_present_upgrades_when_not_required() {
        assert!(prf_forces_uv_upgrade(
            true,
            UserVerificationRequirement::Discouraged
        ));
        assert!(prf_forces_uv_upgrade(
            true,
            UserVerificationRequirement::Preferred
        ));
    }

    #[test]
    fn prf_present_no_change_when_already_required() {
        assert!(!prf_forces_uv_upgrade(
            true,
            UserVerificationRequirement::Required
        ));
    }

    mod limits {
        use super::*;
        use crate::fido::AuthenticatorDataFlags;
        use crate::proto::ctap1::apdu::{ApduRequest, ApduResponse};
        use crate::proto::ctap2::cbor::{self, CborRequest, CborResponse, Value};
        use crate::proto::ctap2::{
            Ctap2CommandCode, Ctap2GetInfoResponse, Ctap2PublicKeyCredentialDescriptor,
            Ctap2PublicKeyCredentialType,
        };
        use crate::transport::mock::channel::MockChannel;
        use crate::transport::{
            device::SupportedProtocols, AuthTokenData, ChannelStatus, Ctap2AuthTokenStore,
        };
        use async_trait::async_trait;
        use serde_bytes::ByteBuf;
        use std::collections::BTreeMap;
        use std::fmt::{Display, Formatter};
        use std::time::Duration;
        use tokio::sync::broadcast;

        /// MockChannel wrapper whose `supports_preflight()` returns false, modelling cable.
        struct NoPreflightChannel {
            inner: MockChannel,
        }

        impl NoPreflightChannel {
            fn new() -> Self {
                Self {
                    inner: MockChannel::new(),
                }
            }

            fn push_command_pair(&mut self, request: CborRequest, response: CborResponse) {
                self.inner.push_command_pair(request, response);
            }
        }

        impl Display for NoPreflightChannel {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, "NoPreflightChannel")
            }
        }

        impl Ctap2AuthTokenStore for NoPreflightChannel {
            fn store_auth_data(&mut self, auth_token_data: AuthTokenData) {
                self.inner.store_auth_data(auth_token_data);
            }
            fn get_auth_data(&self) -> Option<&AuthTokenData> {
                self.inner.get_auth_data()
            }
            fn clear_uv_auth_token_store(&mut self) {
                self.inner.clear_uv_auth_token_store();
            }
            fn set_cred_mgmt_preview(&mut self, uses_preview: bool) {
                self.inner.set_cred_mgmt_preview(uses_preview);
            }
            fn cred_mgmt_preview(&self) -> bool {
                self.inner.cred_mgmt_preview()
            }
        }

        #[async_trait]
        impl Channel for NoPreflightChannel {
            type UxUpdate = UvUpdate;
            type TransportError = std::convert::Infallible;

            fn get_ux_update_sender(&self) -> &broadcast::Sender<Self::UxUpdate> {
                self.inner.get_ux_update_sender()
            }
            async fn supported_protocols(
                &self,
            ) -> Result<SupportedProtocols, WebAuthnError<Self::TransportError>> {
                self.inner.supported_protocols().await
            }
            async fn status(&self) -> ChannelStatus {
                ChannelStatus::Ready
            }
            async fn close(&mut self) {}
            async fn apdu_send(
                &mut self,
                request: &ApduRequest,
                timeout: Duration,
            ) -> Result<(), Self::TransportError> {
                self.inner.apdu_send(request, timeout).await
            }
            async fn apdu_recv(
                &mut self,
                timeout: Duration,
            ) -> Result<ApduResponse, Self::TransportError> {
                self.inner.apdu_recv(timeout).await
            }
            async fn cbor_send(
                &mut self,
                request: &CborRequest,
                timeout: Duration,
            ) -> Result<(), Self::TransportError> {
                self.inner.cbor_send(request, timeout).await
            }
            async fn cbor_recv(
                &mut self,
                timeout: Duration,
            ) -> Result<CborResponse, Self::TransportError> {
                self.inner.cbor_recv(timeout).await
            }
            fn supports_preflight() -> bool {
                false
            }
        }

        fn descriptor(id: &[u8]) -> Ctap2PublicKeyCredentialDescriptor {
            Ctap2PublicKeyCredentialDescriptor {
                id: ByteBuf::from(id.to_vec()),
                r#type: Ctap2PublicKeyCredentialType::PublicKey,
                transports: None,
            }
        }

        fn get_info_response(info: &Ctap2GetInfoResponse) -> CborResponse {
            CborResponse {
                status_code: CtapError::Ok,
                data: Some(cbor::to_vec(info).unwrap()),
            }
        }

        fn rp_id_hash(rp_id: &str) -> Vec<u8> {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::default();
            hasher.update(rp_id.as_bytes());
            hasher.finalize().to_vec()
        }

        fn get_assertion_response_with(
            rp_hash: &[u8],
            credentials_count: Option<u32>,
        ) -> CborResponse {
            let mut auth_data = vec![0u8; 37];
            auth_data[..32].copy_from_slice(rp_hash);
            auth_data[32] = AuthenticatorDataFlags::USER_PRESENT.bits();
            let mut map: BTreeMap<u64, Value> = BTreeMap::new();
            map.insert(0x02, Value::Bytes(auth_data));
            map.insert(0x03, Value::Bytes(vec![0xAAu8; 64]));
            if let Some(count) = credentials_count {
                map.insert(0x05, Value::Integer(count as i128));
            }
            CborResponse {
                status_code: CtapError::Ok,
                data: Some(cbor::to_vec(&map).unwrap()),
            }
        }

        fn get_assertion_response() -> CborResponse {
            get_assertion_response_with(&rp_id_hash("example.com"), None)
        }

        fn assertion_request(
            allow: Vec<Ctap2PublicKeyCredentialDescriptor>,
        ) -> GetAssertionRequest {
            GetAssertionRequest {
                hints: vec![],
                relying_party_id: "example.com".to_string(),
                challenge: vec![0u8; 32],
                origin: "https://example.com".to_string(),
                top_origin: None,
                allow,
                extensions: None,
                user_verification: UserVerificationRequirement::Discouraged,
                timeout: Duration::from_secs(30),
            }
        }

        // Cable has no preflight, so the whole allowList is serialized into one getAssertion.
        // An id longer than maxCredentialIdLength cannot belong to this device and must be
        // dropped before sending (CTAP 2.1/2.2 6.4).
        #[tokio::test]
        async fn oversized_allow_entries_are_filtered_before_send_on_cable() {
            let valid = descriptor(&[1u8; 16]);
            let oversized = descriptor(&[2u8; 64]);
            let info = Ctap2GetInfoResponse {
                max_credential_id_length: Some(32),
                ..Default::default()
            };

            let op = assertion_request(vec![valid.clone(), oversized]);

            // The request that must reach the device: oversized entry removed.
            let expected_request = Ctap2GetAssertionRequest::from_webauthn_request(
                &assertion_request(vec![valid]),
                &info,
            )
            .unwrap();
            let expected_cbor: CborRequest = (&expected_request).try_into().unwrap();

            let mut channel = NoPreflightChannel::new();
            let get_info_request = CborRequest::new(Ctap2CommandCode::AuthenticatorGetInfo);
            channel.push_command_pair(get_info_request.clone(), get_info_response(&info));
            channel.push_command_pair(get_info_request, get_info_response(&info));
            channel.push_command_pair(expected_cbor, get_assertion_response());

            let result = get_assertion_fido2(&mut channel, &op).await;
            assert!(
                result.is_ok(),
                "oversized allowList entry was not filtered before sending: {result:?}"
            );
        }

        fn ctap2_get_assertion(
            allow: Vec<Ctap2PublicKeyCredentialDescriptor>,
        ) -> Ctap2GetAssertionRequest {
            Ctap2GetAssertionRequest {
                relying_party_id: "example.com".to_string(),
                client_data_hash: ByteBuf::from(vec![0u8; 32]),
                allow,
                extensions: None,
                options: None,
                pin_auth_param: None,
                pin_auth_proto: None,
            }
        }

        #[test]
        fn allow_list_over_max_credential_count_is_rejected() {
            let info = Ctap2GetInfoResponse {
                max_credential_count: Some(2),
                ..Default::default()
            };
            let request =
                ctap2_get_assertion(vec![descriptor(b"a"), descriptor(b"b"), descriptor(b"c")]);
            assert_eq!(
                enforce_get_assertion_limits(&request, &info),
                Err(PlatformError::RequestTooLarge)
            );
        }

        #[test]
        fn allow_list_within_max_credential_count_is_accepted() {
            let info = Ctap2GetInfoResponse {
                max_credential_count: Some(2),
                ..Default::default()
            };
            let request = ctap2_get_assertion(vec![descriptor(b"a"), descriptor(b"b")]);
            assert_eq!(enforce_get_assertion_limits(&request, &info), Ok(()));
        }

        #[test]
        fn exclude_list_over_max_credential_count_is_rejected() {
            let info = Ctap2GetInfoResponse {
                max_credential_count: Some(1),
                ..Default::default()
            };
            let mut request = Ctap2MakeCredentialRequest::dummy();
            request.exclude = Some(vec![descriptor(b"a"), descriptor(b"b")]);
            assert_eq!(
                enforce_make_credential_limits(&request, &info),
                Err(PlatformError::RequestTooLarge)
            );
        }

        // maxMsgSize is absent, so the 1024-byte spec default must bound the request.
        #[test]
        fn request_over_default_max_msg_size_is_rejected() {
            let info = Ctap2GetInfoResponse::default();
            assert_eq!(info.max_msg_size(), 1024);
            // A single 2000-byte credential id keeps the count at 1 but blows past 1024 bytes.
            let request = ctap2_get_assertion(vec![descriptor(&[0u8; 2000])]);
            assert_eq!(
                enforce_get_assertion_limits(&request, &info),
                Err(PlatformError::RequestTooLarge)
            );
        }

        #[test]
        fn request_within_default_max_msg_size_is_accepted() {
            let info = Ctap2GetInfoResponse::default();
            let request = ctap2_get_assertion(vec![descriptor(&[0u8; 16])]);
            assert_eq!(enforce_get_assertion_limits(&request, &info), Ok(()));
        }

        #[tokio::test]
        async fn get_next_assertion_iteration_is_bounded() {
            let info = Ctap2GetInfoResponse {
                max_credential_count: Some(2),
                ..Default::default()
            };
            let op = assertion_request(vec![]);
            let expected_request =
                Ctap2GetAssertionRequest::from_webauthn_request(&op, &info).unwrap();
            let expected_cbor: CborRequest = (&expected_request).try_into().unwrap();

            let hash = rp_id_hash("example.com");
            let mut channel = NoPreflightChannel::new();
            let get_info_request = CborRequest::new(Ctap2CommandCode::AuthenticatorGetInfo);
            channel.push_command_pair(get_info_request.clone(), get_info_response(&info));
            channel.push_command_pair(get_info_request, get_info_response(&info));
            channel.push_command_pair(
                expected_cbor,
                get_assertion_response_with(&hash, Some(u32::MAX)),
            );
            // Only one getNextAssertion is queued, so unbounded iteration would panic.
            let next_request = CborRequest::new(Ctap2CommandCode::AuthenticatorGetNextAssertion);
            channel.push_command_pair(next_request, get_assertion_response_with(&hash, None));

            let result = get_assertion_fido2(&mut channel, &op).await;
            assert!(result.is_ok(), "bounded iteration failed: {result:?}");
        }

        #[tokio::test]
        async fn mismatched_rp_id_hash_is_rejected() {
            let info = Ctap2GetInfoResponse::default();
            let op = assertion_request(vec![]);
            let expected_request =
                Ctap2GetAssertionRequest::from_webauthn_request(&op, &info).unwrap();
            let expected_cbor: CborRequest = (&expected_request).try_into().unwrap();

            let mut channel = NoPreflightChannel::new();
            let get_info_request = CborRequest::new(Ctap2CommandCode::AuthenticatorGetInfo);
            channel.push_command_pair(get_info_request.clone(), get_info_response(&info));
            channel.push_command_pair(get_info_request, get_info_response(&info));
            channel.push_command_pair(
                expected_cbor,
                get_assertion_response_with(&[0xFFu8; 32], None),
            );

            let result = get_assertion_fido2(&mut channel, &op).await;
            assert!(matches!(
                result.err(),
                Some(WebAuthnError::Platform(
                    PlatformError::InvalidDeviceResponse
                ))
            ));
        }
    }
}
