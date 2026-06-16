use decmed_rme_segment::{ DatasetCategory, FunctionCategory };
use serde::{ Deserialize, Serialize };

use crate::effective::AccessMode;
use crate::errors::CaveatVerificationError;

/// Canonical request context signed by the active wallet for every DecMed token request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletProofContext {
    pub token_id: String,
    pub patient_address: String,
    pub related_rme_id: String,
    pub operation: AccessMode,
    pub segment_id: String,
    pub dataset_category: DatasetCategory,
    pub function_category: FunctionCategory,
    pub timestamp: String,
}

impl WalletProofContext {
    pub fn canonical_message(&self) -> Result<String, CaveatVerificationError> {
        serde_json::to_string(self).map_err(|e| CaveatVerificationError::ParseError(e.to_string()))
    }
}

pub trait WalletSignatureVerifier {
    fn verify(
        &self,
        context: &WalletProofContext,
        signature_b64: &str,
        expected_address: &str
    ) -> Result<(), CaveatVerificationError>;
}
