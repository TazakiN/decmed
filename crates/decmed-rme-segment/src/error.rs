use std::{ error::Error, fmt };

use crate::category::{ DatasetCategory, FunctionCategory };

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SegmentValidationError {
    EmptyPayload,
    ForbiddenOnChainField(String),
    InconsistentField(&'static str),
    InvalidAdministrativePayload(String),
    InvalidCategoryCombination {
        dataset_category: DatasetCategory,
        function_category: FunctionCategory,
    },
    InvalidCiphertext,
    InvalidCorrection(&'static str),
    InvalidIntegrityHash,
    InvalidPayloadHash,
    InvalidUuid,
    MissingField(&'static str),
    SerializationFailed,
}

impl fmt::Display for SegmentValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPayload => write!(f, "segment payload must not be empty"),
            Self::ForbiddenOnChainField(field) => {
                write!(f, "on-chain metadata contains forbidden field `{field}`")
            }
            Self::InconsistentField(field) => {
                write!(f, "off-chain segment and on-chain metadata differ on `{field}`")
            }
            Self::InvalidAdministrativePayload(message) => {
                write!(f, "invalid administrative general payload: {message}")
            }
            Self::InvalidCategoryCombination { dataset_category, function_category } =>
                write!(
                    f,
                    "invalid segment category combination: {:?} + {:?}",
                    dataset_category,
                    function_category
                ),
            Self::InvalidCiphertext => write!(f, "encrypted segment is not valid base64"),
            Self::InvalidCorrection(message) => {
                write!(f, "invalid segment correction: {message}")
            }
            Self::InvalidIntegrityHash => {
                write!(f, "integrity_hash does not match encrypted segment")
            }
            Self::InvalidPayloadHash => write!(f, "payload_hash does not match canonical payload"),
            Self::InvalidUuid => write!(f, "segment_id must be a valid UUID"),
            Self::MissingField(field) => write!(f, "missing required field `{field}`"),
            Self::SerializationFailed => write!(f, "failed to serialize segment structure"),
        }
    }
}

impl Error for SegmentValidationError {}
