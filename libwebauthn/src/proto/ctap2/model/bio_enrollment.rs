use super::Ctap2PinUvAuthProtocol;
use serde_bytes::ByteBuf;
use serde_indexed::{DeserializeIndexed, SerializeIndexed};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::time::Duration;

#[derive(Debug, Clone, SerializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct Ctap2BioEnrollmentRequest {
    // modality (0x01) 	Unsigned Integer 	Optional 	The user verification modality being requested
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x01)]
    pub modality: Option<Ctap2BioEnrollmentModality>,

    // subCommand (0x02) 	Unsigned Integer 	Optional 	The authenticator user verification sub command currently being requested
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x02)]
    pub subcommand: Option<Ctap2BioEnrollmentSubcommand>,

    // subCommandParams (0x03) 	CBOR Map 	Optional 	Map of subCommands parameters. This parameter MAY be omitted when the subCommand does not take any arguments.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x03)]
    pub subcommand_params: Option<Ctap2BioEnrollmentParams>,

    // pinUvAuthProtocol (0x04) 	Unsigned Integer 	Optional 	PIN/UV protocol version chosen by the platform.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x04)]
    pub protocol: Option<Ctap2PinUvAuthProtocol>,

    // pinUvAuthParam (0x05) 	Byte String 	Optional 	First 16 bytes of HMAC-SHA-256 of contents using pinUvAuthToken.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x05)]
    pub uv_auth_param: Option<ByteBuf>,

    // getModality (0x06) 	Boolean 	Optional 	Get the user verification type modality. This MUST be set to true.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x06)]
    pub get_modality: Option<bool>,

    #[serde(skip)]
    pub use_legacy_preview: bool,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, FromPrimitive, PartialEq, Serialize_repr, Deserialize_repr)]
pub enum Ctap2BioEnrollmentSubcommand {
    EnrollBegin = 0x01,
    EnrollCaptureNextSample = 0x02,
    CancelCurrentEnrollment = 0x03,
    EnumerateEnrollments = 0x04,
    SetFriendlyName = 0x05,
    RemoveEnrollment = 0x06,
    GetFingerprintSensorInfo = 0x07,
}

#[derive(Debug, Clone, SerializeIndexed)]
pub struct Ctap2BioEnrollmentParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x01)]
    template_id: Option<ByteBuf>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x02)]
    template_friendly_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x03)]
    timeout_milliseconds: Option<u64>,
}

#[derive(Debug, Default, Clone, DeserializeIndexed)]
pub struct Ctap2BioEnrollmentResponse {
    // modality (0x01) 	Unsigned Integer 	Optional 	The user verification modality.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x01)]
    pub modality: Option<Ctap2BioEnrollmentModality>,

    // fingerprintKind (0x02) 	Unsigned Integer 	Optional 	Indicates the type of fingerprint sensor. For touch type sensor, its value is 1. For swipe type sensor its value is 2.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x02)]
    pub fingerprint_kind: Option<Ctap2BioEnrollmentFingerprintKind>,

    // maxCaptureSamplesRequiredForEnroll (0x03) 	Unsigned Integer 	Optional 	Indicates the maximum good samples required for enrollment.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x03)]
    pub max_capture_samples_required_for_enroll: Option<u64>,

    // templateId (0x04) 	Byte String 	Optional 	Template Identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x04)]
    pub template_id: Option<ByteBuf>,

    // lastEnrollSampleStatus (0x05) 	Unsigned Integer 	Optional 	Last enrollment sample status.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x05)]
    pub last_enroll_sample_status: Option<Ctap2LastEnrollmentSampleStatus>,

    // remainingSamples (0x06) 	Unsigned Integer 	Optional 	Number of more sample required for enrollment to complete
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x06)]
    pub remaining_samples: Option<u64>,

    // templateInfos (0x07) 	CBOR ARRAY 	Optional 	Array of templateInfo’s
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x07)]
    pub template_infos: Option<Vec<Ctap2BioEnrollmentTemplateId>>,

    // maxTemplateFriendlyName (0x08) 	Unsigned Integer 	Optional 	Indicates the maximum number of bytes the authenticator will accept as a templateFriendlyName.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x08)]
    pub max_template_friendly_name: Option<u64>,
}

#[derive(Debug, Clone, DeserializeIndexed)]
pub struct Ctap2BioEnrollmentTemplateId {
    // templateId (0x01) 	Byte String 	Required 	Template Identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x01)]
    pub template_id: Option<ByteBuf>,

    // templateFriendlyName (0x02) 	String 	Optional 	Template Friendly Name.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x02)]
    pub template_friendly_name: Option<String>,
}

#[repr(u64)]
#[derive(Debug, Clone, Copy, FromPrimitive, PartialEq, Serialize_repr, Deserialize_repr)]
pub enum Ctap2LastEnrollmentSampleStatus {
    Ctap2EnrollFeedbackFpGood = 0x00,        // Good fingerprint capture.
    Ctap2EnrollFeedbackFpTooHigh = 0x01,     // Fingerprint was too high.
    Ctap2EnrollFeedbackFpTooLow = 0x02,      // Fingerprint was too low.
    Ctap2EnrollFeedbackFpTooLeft = 0x03,     // Fingerprint was too left.
    Ctap2EnrollFeedbackFpTooRight = 0x04,    // Fingerprint was too right.
    Ctap2EnrollFeedbackFpTooFast = 0x05,     // Fingerprint was too fast.
    Ctap2EnrollFeedbackFpTooSlow = 0x06,     // Fingerprint was too slow.
    Ctap2EnrollFeedbackFpPoorQuality = 0x07, // Fingerprint was of poor quality.
    Ctap2EnrollFeedbackFpTooSkewed = 0x08,   // Fingerprint was too skewed.
    Ctap2EnrollFeedbackFpTooShort = 0x09,    // Fingerprint was too short.
    Ctap2EnrollFeedbackFpMergeFailure = 0x0A, // Merge failure of the capture.
    Ctap2EnrollFeedbackFpExists = 0x0B,      // Fingerprint already exists.
    Unused = 0x0C,                           // (this error number is available)
    Ctap2EnrollFeedbackNoUserActivity = 0x0D, // User did not touch/swipe the authenticator.
    Ctap2EnrollFeedbackNoUserPresenceTransition = 0x0E, // User did not lift the finger off the sensor.
}

#[repr(u64)]
#[derive(Debug, Clone, FromPrimitive, PartialEq, Serialize_repr, Deserialize_repr)]
pub enum Ctap2BioEnrollmentModality {
    Fingerprint = 0x01, // Fingerprint was too high.
}

#[repr(u64)]
#[derive(Debug, Clone, FromPrimitive, PartialEq, Serialize_repr, Deserialize_repr)]
pub enum Ctap2BioEnrollmentFingerprintKind {
    Touch = 0x01,
    Swipe = 0x02,
}

impl Ctap2BioEnrollmentRequest {
    pub fn new_get_modality() -> Self {
        Ctap2BioEnrollmentRequest {
            modality: None,
            subcommand: None,
            subcommand_params: None,
            protocol: None,      // Get's filled in later
            uv_auth_param: None, // Get's filled in later
            get_modality: Some(true),
            use_legacy_preview: false,
        }
    }

    pub fn new_fingerprint_sensor_info() -> Self {
        Ctap2BioEnrollmentRequest {
            modality: Some(Ctap2BioEnrollmentModality::Fingerprint),
            subcommand: Some(Ctap2BioEnrollmentSubcommand::GetFingerprintSensorInfo),
            subcommand_params: None,
            protocol: None,      // Get's filled in later
            uv_auth_param: None, // Get's filled in later
            get_modality: None,
            use_legacy_preview: false,
        }
    }

    pub fn new_enumerate_enrollments() -> Self {
        Ctap2BioEnrollmentRequest {
            modality: Some(Ctap2BioEnrollmentModality::Fingerprint),
            subcommand: Some(Ctap2BioEnrollmentSubcommand::EnumerateEnrollments),
            subcommand_params: None,
            protocol: None,      // Get's filled in later
            uv_auth_param: None, // Get's filled in later
            get_modality: None,
            use_legacy_preview: false,
        }
    }

    pub fn new_remove_enrollment(template_id: &[u8]) -> Self {
        Ctap2BioEnrollmentRequest {
            modality: Some(Ctap2BioEnrollmentModality::Fingerprint),
            subcommand: Some(Ctap2BioEnrollmentSubcommand::RemoveEnrollment),
            subcommand_params: Some(Ctap2BioEnrollmentParams {
                template_id: Some(ByteBuf::from(template_id)),
                template_friendly_name: None,
                timeout_milliseconds: None,
            }),
            protocol: None,      // Get's filled in later
            uv_auth_param: None, // Get's filled in later
            get_modality: None,
            use_legacy_preview: false,
        }
    }

    pub fn new_rename_enrollment(template_id: &[u8], template_friendly_name: &str) -> Self {
        Ctap2BioEnrollmentRequest {
            modality: Some(Ctap2BioEnrollmentModality::Fingerprint),
            subcommand: Some(Ctap2BioEnrollmentSubcommand::SetFriendlyName),
            subcommand_params: Some(Ctap2BioEnrollmentParams {
                template_id: Some(ByteBuf::from(template_id)),
                template_friendly_name: Some(template_friendly_name.to_string()),
                timeout_milliseconds: None,
            }),
            protocol: None,      // Get's filled in later
            uv_auth_param: None, // Get's filled in later
            get_modality: None,
            use_legacy_preview: false,
        }
    }

    pub fn new_start_new_enrollment(enrollment_timeout: Option<Duration>) -> Self {
        let subcommand_params = if let Some(time) = enrollment_timeout {
            Some(Ctap2BioEnrollmentParams {
                template_id: None,
                template_friendly_name: None,
                timeout_milliseconds: Some(time.as_millis() as u64),
            })
        } else {
            None
        };

        Ctap2BioEnrollmentRequest {
            modality: Some(Ctap2BioEnrollmentModality::Fingerprint),
            subcommand: Some(Ctap2BioEnrollmentSubcommand::EnrollBegin),
            subcommand_params,
            protocol: None,      // Get's filled in later
            uv_auth_param: None, // Get's filled in later
            get_modality: None,
            use_legacy_preview: false,
        }
    }

    pub fn new_next_enrollment(template_id: &[u8], enrollment_timeout: Option<Duration>) -> Self {
        let subcommand_params = Some(Ctap2BioEnrollmentParams {
            template_id: Some(ByteBuf::from(template_id)),
            template_friendly_name: None,
            timeout_milliseconds: enrollment_timeout.map(|x| x.as_millis() as u64),
        });

        Ctap2BioEnrollmentRequest {
            modality: Some(Ctap2BioEnrollmentModality::Fingerprint),
            subcommand: Some(Ctap2BioEnrollmentSubcommand::EnrollCaptureNextSample),
            subcommand_params,
            protocol: None,
            uv_auth_param: None,
            get_modality: None,
            use_legacy_preview: false,
        }
    }

    pub fn new_cancel_current_enrollment() -> Self {
        Ctap2BioEnrollmentRequest {
            modality: Some(Ctap2BioEnrollmentModality::Fingerprint),
            subcommand: Some(Ctap2BioEnrollmentSubcommand::CancelCurrentEnrollment),
            subcommand_params: None,
            protocol: None,
            uv_auth_param: None,
            get_modality: None,
            use_legacy_preview: false,
        }
    }
}
