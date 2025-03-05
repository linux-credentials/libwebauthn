use crate::{
    ops::webauthn::UserVerificationRequirement,
    pin::{PinUvAuthProtocol, UvProvider},
    proto::ctap2::{
        Ctap2, Ctap2AuthTokenPermissionRole, Ctap2BioEnrollmentFingerprintKind,
        Ctap2BioEnrollmentModality, Ctap2BioEnrollmentRequest, Ctap2BioEnrollmentTemplateId,
        Ctap2ClientPinRequest, Ctap2GetInfoResponse, Ctap2LastEnrollmentSampleStatus,
        Ctap2UserVerifiableRequest,
    },
    transport::{
        error::{CtapError, Error, PlatformError},
        Channel,
    },
    unwrap_field,
    webauthn::{handle_errors, user_verification, UsedPinUvAuthToken},
};
use async_trait::async_trait;
use serde_bytes::ByteBuf;
use serde_cbor::ser::to_vec;
use std::time::Duration;
use tracing::info;

#[async_trait]
pub trait BioEnrollment {
    async fn get_bio_modality(
        &mut self,
        timeout: Duration,
    ) -> Result<Ctap2BioEnrollmentModality, Error>;
    async fn get_fingerprint_sensor_info(
        &mut self,
        timeout: Duration,
    ) -> Result<Ctap2BioEnrollmentFingerprintSensorInfo, Error>;
    async fn get_bio_enrollments(
        &mut self,
        pin_provider: &mut Box<dyn UvProvider>,
        timeout: Duration,
    ) -> Result<Vec<Ctap2BioEnrollmentTemplateId>, Error>;
    async fn remove_bio_enrollment(
        &mut self,
        template_id: &[u8],
        pin_provider: &mut Box<dyn UvProvider>,
        timeout: Duration,
    ) -> Result<(), Error>;
    async fn rename_bio_enrollment(
        &mut self,
        template_id: &[u8],
        template_friendly_name: &str,
        pin_provider: &mut Box<dyn UvProvider>,
        timeout: Duration,
    ) -> Result<(), Error>;
    async fn start_new_bio_enrollment(
        &mut self,
        pin_provider: &mut Box<dyn UvProvider>,
        enrollment_timeout: Option<Duration>,
        timeout: Duration,
    ) -> Result<(Vec<u8>, Ctap2LastEnrollmentSampleStatus, u64), Error>;
    async fn capture_next_bio_enrollment_sample(
        &mut self,
        template_id: &[u8],
        pin_provider: &mut Box<dyn UvProvider>,
        enrollment_timeout: Option<Duration>,
        timeout: Duration,
    ) -> Result<(Ctap2LastEnrollmentSampleStatus, u64), Error>;
    async fn cancel_current_bio_enrollment(
        &mut self,
        pin_provider: &mut Box<dyn UvProvider>,
        timeout: Duration,
    ) -> Result<(), Error>;
}

#[derive(Debug, Clone)]
pub struct Ctap2BioEnrollmentFingerprintSensorInfo {
    pub fingerprint_kind: Ctap2BioEnrollmentFingerprintKind,
    pub max_capture_samples_required_for_enroll: Option<u64>,
    /// Not returned/supported by BioEnrollmentPreview
    pub max_template_friendly_name: Option<u64>,
}

#[async_trait]
impl<C> BioEnrollment for C
where
    C: Channel,
{
    async fn get_bio_modality(
        &mut self,
        timeout: Duration,
    ) -> Result<Ctap2BioEnrollmentModality, Error> {
        let req = Ctap2BioEnrollmentRequest::new_get_modality();
        // No UV needed
        let resp = self.ctap2_bio_enrollment(&req, timeout).await?;
        resp.modality.ok_or(Error::Ctap(CtapError::Other))
    }

    async fn get_fingerprint_sensor_info(
        &mut self,
        timeout: Duration,
    ) -> Result<Ctap2BioEnrollmentFingerprintSensorInfo, Error> {
        let req = Ctap2BioEnrollmentRequest::new_fingerprint_sensor_info();
        // No UV needed
        let resp = self.ctap2_bio_enrollment(&req, timeout).await?;
        Ok(Ctap2BioEnrollmentFingerprintSensorInfo {
            fingerprint_kind: resp.fingerprint_kind.ok_or(Error::Ctap(CtapError::Other))?,
            max_capture_samples_required_for_enroll: resp
                .max_capture_samples_required_for_enroll
                .clone(),
            max_template_friendly_name: resp.max_template_friendly_name,
        })
    }

    async fn get_bio_enrollments(
        &mut self,
        pin_provider: &mut Box<dyn UvProvider>,
        timeout: Duration,
    ) -> Result<Vec<Ctap2BioEnrollmentTemplateId>, Error> {
        let mut req = Ctap2BioEnrollmentRequest::new_enumerate_enrollments();

        let resp = loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Preferred,
                &mut req,
                pin_provider,
                timeout,
            )
            .await?;

            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_bio_enrollment(&req, timeout).await,
                uv_auth_used,
                pin_provider,
                timeout
            )
        };
        Ok(resp?.template_infos.unwrap_or_default())
    }

    async fn remove_bio_enrollment(
        &mut self,
        template_id: &[u8],
        pin_provider: &mut Box<dyn UvProvider>,
        timeout: Duration,
    ) -> Result<(), Error> {
        let mut req = Ctap2BioEnrollmentRequest::new_remove_enrollment(template_id);

        loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Preferred,
                &mut req,
                pin_provider,
                timeout,
            )
            .await?;

            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_bio_enrollment(&req, timeout).await,
                uv_auth_used,
                pin_provider,
                timeout
            )
        }?;

        // "If there is an exiting enrollment with passed in templateInfo, delete that enrollment and return CTAP2_OK."
        // So, the resulting Response will be empty on success.
        Ok(())
    }

    async fn rename_bio_enrollment(
        &mut self,
        template_id: &[u8],
        template_friendly_name: &str,
        pin_provider: &mut Box<dyn UvProvider>,
        timeout: Duration,
    ) -> Result<(), Error> {
        let mut req =
            Ctap2BioEnrollmentRequest::new_rename_enrollment(template_id, template_friendly_name);
        loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Preferred,
                &mut req,
                pin_provider,
                timeout,
            )
            .await?;

            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_bio_enrollment(&req, timeout).await,
                uv_auth_used,
                pin_provider,
                timeout
            )
        }?;
        // "If there is an exiting enrollment with passed in templateInfo, delete that enrollment and return CTAP2_OK."
        // So, the resulting Response will be empty on success.
        Ok(())
    }

    async fn start_new_bio_enrollment(
        &mut self,
        pin_provider: &mut Box<dyn UvProvider>,
        enrollment_timeout: Option<Duration>,
        timeout: Duration,
    ) -> Result<(Vec<u8>, Ctap2LastEnrollmentSampleStatus, u64), Error> {
        let mut req = Ctap2BioEnrollmentRequest::new_start_new_enrollment(enrollment_timeout);

        let resp = loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Preferred,
                &mut req,
                pin_provider,
                timeout,
            )
            .await?;

            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_bio_enrollment(&req, timeout).await,
                uv_auth_used,
                pin_provider,
                timeout
            )
        }?;

        let remaining_samples = unwrap_field!(resp.remaining_samples);
        let template_id = unwrap_field!(resp.template_id).clone();
        let sample_status = unwrap_field!(resp.last_enroll_sample_status);
        Ok((template_id.to_vec(), sample_status, remaining_samples))
    }

    async fn capture_next_bio_enrollment_sample(
        &mut self,
        template_id: &[u8],
        pin_provider: &mut Box<dyn UvProvider>,
        enrollment_timeout: Option<Duration>,
        timeout: Duration,
    ) -> Result<(Ctap2LastEnrollmentSampleStatus, u64), Error> {
        let mut req =
            Ctap2BioEnrollmentRequest::new_next_enrollment(template_id, enrollment_timeout);

        let resp = loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Preferred,
                &mut req,
                pin_provider,
                timeout,
            )
            .await?;

            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_bio_enrollment(&req, timeout).await,
                uv_auth_used,
                pin_provider,
                timeout
            )
        }?;

        let remaining_samples = unwrap_field!(resp.remaining_samples);
        let sample_status = unwrap_field!(resp.last_enroll_sample_status);
        Ok((sample_status, remaining_samples))
    }

    async fn cancel_current_bio_enrollment(
        &mut self,
        pin_provider: &mut Box<dyn UvProvider>,
        timeout: Duration,
    ) -> Result<(), Error> {
        let mut req = Ctap2BioEnrollmentRequest::new_cancel_current_enrollment();

        loop {
            let uv_auth_used = user_verification(
                self,
                UserVerificationRequirement::Preferred,
                &mut req,
                pin_provider,
                timeout,
            )
            .await?;

            // On success, this is an all-empty Ctap2AuthenticatorConfigResponse
            handle_errors!(
                self,
                self.ctap2_bio_enrollment(&req, timeout).await,
                uv_auth_used,
                pin_provider,
                timeout
            )
        }?;

        // "Authenticator on receiving such command, cancels current ongoing enrollment, if any, and returns CTAP2_OK."
        // So, the resulting Response will be empty on success.
        Ok(())
    }
}

impl Ctap2UserVerifiableRequest for Ctap2BioEnrollmentRequest {
    fn ensure_uv_set(&mut self) {
        // No-op
    }

    fn calculate_and_set_uv_auth(
        &mut self,
        uv_proto: &Box<dyn PinUvAuthProtocol>,
        uv_auth_token: &[u8],
    ) {
        // pinUvAuthParam (0x05): authenticate(pinUvAuthToken, fingerprint (0x01) || enumerateEnrollments (0x04)).
        let mut data = match self.subcommand {
            None => unreachable!(),
            Some(x) => {
                let data = vec![Ctap2BioEnrollmentModality::Fingerprint as u8, x as u8];
                data
            }
        };
        // e.g. "Authenticator calls verify(pinUvAuthToken, fingerprint (0x01) || removeEnrollment (0x06) || subCommandParams, pinUvAuthParam)"
        if let Some(params) = &self.subcommand_params {
            data.extend(to_vec(params).unwrap());
        }
        let uv_auth_param = uv_proto.authenticate(uv_auth_token, &data);
        self.protocol = Some(uv_proto.version());
        self.uv_auth_param = Some(ByteBuf::from(uv_auth_param));
    }

    fn client_data_hash(&self) -> &[u8] {
        unreachable!()
    }

    fn permissions(&self) -> Ctap2AuthTokenPermissionRole {
        return Ctap2AuthTokenPermissionRole::BIO_ENROLLMENT;
    }

    fn permissions_rpid(&self) -> Option<&str> {
        None
    }

    fn can_use_uv(&self, info: &Ctap2GetInfoResponse) -> bool {
        info.option_enabled("uvBioEnroll")
    }

    fn handle_legacy_preview(&mut self, info: &Ctap2GetInfoResponse) {
        if let Some(options) = &info.options {
            // According to Spec, we would also need to verify the token only
            // supports FIDO_2_1_PRE, but let's be a bit less strict here and
            // accept it simply reporting preview-support, but not the real one.
            if options.get("bioEnroll") != Some(&true)
                && options.get("userVerificationMgmtPreview") == Some(&true)
            {
                self.use_legacy_preview = true;
            }
        }
    }
}
