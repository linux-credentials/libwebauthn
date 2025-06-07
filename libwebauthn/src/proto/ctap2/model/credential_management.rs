use super::{
    Ctap2PinUvAuthProtocol, Ctap2PublicKeyCredentialDescriptor, Ctap2PublicKeyCredentialRpEntity,
    Ctap2PublicKeyCredentialUserEntity,
};
use cosey::PublicKey;
use serde_bytes::ByteBuf;
use serde_indexed::{DeserializeIndexed, SerializeIndexed};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Debug, Clone, SerializeIndexed)]
pub struct Ctap2CredentialManagementRequest {
    //subCommand (0x01) 	Unsigned Integer 	subCommand currently being requested
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x01)]
    pub subcommand: Option<Ctap2CredentialManagementSubcommand>,

    //subCommandParams (0x02) 	CBOR Map 	Map of subCommands parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x02)]
    pub subcommand_params: Option<Ctap2CredentialManagementParams>,

    //pinUvAuthProtocol (0x03) 	Unsigned Integer 	PIN/UV protocol version chosen by the platform.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x03)]
    pub protocol: Option<Ctap2PinUvAuthProtocol>,

    //pinUvAuthParam (0x04) 	Byte String 	First 16 bytes of HMAC-SHA-256 of contents using pinUvAuthToken.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x04)]
    pub uv_auth_param: Option<ByteBuf>,

    #[serde(skip)]
    pub use_legacy_preview: bool,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, FromPrimitive, PartialEq, Serialize_repr, Deserialize_repr)]
pub enum Ctap2CredentialManagementSubcommand {
    GetCredsMetadata = 0x01,
    EnumerateRPsBegin = 0x02,
    EnumerateRPsGetNextRP = 0x03,
    EnumerateCredentialsBegin = 0x04,
    EnumerateCredentialsGetNextCredential = 0x05,
    DeleteCredential = 0x06,
    UpdateUserInformation = 0x07,
}

#[derive(Debug, Clone, SerializeIndexed)]
pub struct Ctap2CredentialManagementParams {
    // rpIDHash (0x01) 	Byte String 	RP ID SHA-256 hash
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x01)]
    rpid_hash: Option<ByteBuf>,

    // credentialID (0x02) 	PublicKeyCredentialDescriptor 	Credential Identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x02)]
    credential_id: Option<Ctap2PublicKeyCredentialDescriptor>,

    // user (0x03) 	PublicKeyCredentialUserEntity 	User Entity
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x03)]
    user: Option<Ctap2PublicKeyCredentialUserEntity>,
}

#[derive(Debug, Default, Clone, DeserializeIndexed)]
pub struct Ctap2CredentialManagementResponse {
    // existingResidentCredentialsCount (0x01) 	Unsigned Integer 	Number of existing discoverable credentials present on the authenticator.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x01)]
    pub existing_resident_credentials_count: Option<u64>,

    // maxPossibleRemainingResidentCredentialsCount (0x02) 	Unsigned Integer 	Number of maximum possible remaining discoverable credentials which can be created on the authenticator.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x02)]
    pub max_possible_remaining_resident_credentials_count: Option<u64>,

    // rp (0x03) 	PublicKeyCredentialRpEntity 	RP Information
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x03)]
    pub rp: Option<Ctap2PublicKeyCredentialRpEntity>,

    // rpIDHash (0x04) 	Byte String 	RP ID SHA-256 hash
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x04)]
    pub rp_id_hash: Option<ByteBuf>,

    // totalRPs (0x05) 	Unsigned Integer 	total number of RPs present on the authenticator
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x05)]
    pub total_rps: Option<u64>,

    // user (0x06) 	PublicKeyCredentialUserEntity 	User Information
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x06)]
    pub user: Option<Ctap2PublicKeyCredentialUserEntity>,

    // credentialID (0x07) 	PublicKeyCredentialDescriptor 	PublicKeyCredentialDescriptor
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x07)]
    pub credential_id: Option<Ctap2PublicKeyCredentialDescriptor>,

    // publicKey (0x08) 	COSE_Key 	Public key of the credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x08)]
    pub public_key: Option<PublicKey>,

    // totalCredentials (0x09) 	Unsigned Integer 	Total number of credentials present on the authenticator for the RP in question
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x09)]
    pub total_credentials: Option<u64>,

    // credProtect (0x0A) 	Unsigned Integer 	Credential protection policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x0A)]
    pub cred_protect: Option<u64>,

    // largeBlobKey (0x0B) 	Byte string 	Large blob encryption key.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(index = 0x0B)]
    pub large_blob_key: Option<ByteBuf>,
}

impl Ctap2CredentialManagementRequest {
    pub fn new_get_credential_metadata() -> Self {
        Ctap2CredentialManagementRequest {
            subcommand: Some(Ctap2CredentialManagementSubcommand::GetCredsMetadata),
            subcommand_params: None,
            protocol: None,
            uv_auth_param: None,
            use_legacy_preview: false,
        }
    }

    pub fn new_enumerate_rps_begin() -> Self {
        Ctap2CredentialManagementRequest {
            subcommand: Some(Ctap2CredentialManagementSubcommand::EnumerateRPsBegin),
            subcommand_params: None,
            protocol: None,
            uv_auth_param: None,
            use_legacy_preview: false,
        }
    }

    pub fn new_enumerate_rps_next_rp() -> Self {
        Ctap2CredentialManagementRequest {
            subcommand: Some(Ctap2CredentialManagementSubcommand::EnumerateRPsGetNextRP),
            subcommand_params: None,
            protocol: None,
            uv_auth_param: None,
            use_legacy_preview: false,
        }
    }

    pub fn new_enumerate_credentials_begin(rpid_hash: &[u8]) -> Self {
        Ctap2CredentialManagementRequest {
            subcommand: Some(Ctap2CredentialManagementSubcommand::EnumerateCredentialsBegin),
            subcommand_params: Some(Ctap2CredentialManagementParams {
                rpid_hash: Some(ByteBuf::from(rpid_hash)),
                credential_id: None,
                user: None,
            }),
            protocol: None,
            uv_auth_param: None,
            use_legacy_preview: false,
        }
    }

    pub fn new_enumerate_credentials_next() -> Self {
        Ctap2CredentialManagementRequest {
            subcommand: Some(
                Ctap2CredentialManagementSubcommand::EnumerateCredentialsGetNextCredential,
            ),
            subcommand_params: None,
            protocol: None,
            uv_auth_param: None,
            use_legacy_preview: false,
        }
    }

    pub fn new_delete_credential(credential_id: &Ctap2PublicKeyCredentialDescriptor) -> Self {
        Ctap2CredentialManagementRequest {
            subcommand: Some(Ctap2CredentialManagementSubcommand::DeleteCredential),
            subcommand_params: Some(Ctap2CredentialManagementParams {
                rpid_hash: None,
                credential_id: Some(credential_id.clone()),
                user: None,
            }),
            protocol: None,
            uv_auth_param: None,
            use_legacy_preview: false,
        }
    }

    pub fn new_update_user_information(
        credential_id: &Ctap2PublicKeyCredentialDescriptor,
        user: &Ctap2PublicKeyCredentialUserEntity,
    ) -> Self {
        Ctap2CredentialManagementRequest {
            subcommand: Some(Ctap2CredentialManagementSubcommand::UpdateUserInformation),
            subcommand_params: Some(Ctap2CredentialManagementParams {
                rpid_hash: None,
                credential_id: Some(credential_id.clone()),
                user: Some(user.clone()),
            }),
            protocol: None,
            uv_auth_param: None,
            use_legacy_preview: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Ctap2CredentialManagementMetadata {
    pub existing_resident_credentials_count: u64,
    pub max_possible_remaining_resident_credentials_count: u64,
}

impl Ctap2CredentialManagementMetadata {
    pub fn new(
        existing_resident_credentials_count: u64,
        max_possible_remaining_resident_credentials_count: u64,
    ) -> Self {
        Self {
            existing_resident_credentials_count,
            max_possible_remaining_resident_credentials_count,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Ctap2CredentialData {
    pub user: Ctap2PublicKeyCredentialUserEntity,
    pub credential_id: Ctap2PublicKeyCredentialDescriptor,
    pub public_key: PublicKey,
    pub cred_protect: u64,
    /// This is not there in the Preview mode
    pub large_blob_key: Option<Vec<u8>>,
}

impl Ctap2CredentialData {
    pub fn new(
        user: Ctap2PublicKeyCredentialUserEntity,
        credential_id: Ctap2PublicKeyCredentialDescriptor,
        public_key: PublicKey,
        cred_protect: u64,
        large_blob_key: Option<Vec<u8>>,
    ) -> Self {
        Self {
            user,
            credential_id,
            public_key,
            cred_protect,
            large_blob_key,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Ctap2RPData {
    pub rp: Ctap2PublicKeyCredentialRpEntity,
    pub rp_id_hash: Vec<u8>,
}

impl Ctap2RPData {
    pub fn new(rp: Ctap2PublicKeyCredentialRpEntity, rp_id_hash: Vec<u8>) -> Self {
        Self { rp, rp_id_hash }
    }
}
