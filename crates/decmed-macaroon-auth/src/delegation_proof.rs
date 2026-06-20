use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::attenuation::DelegationAttenuationParams;
use crate::caveats::{
    format_dataset_list, format_function_list, CaveatKey, CaveatValue, ParsedCaveats,
};
use crate::delegation::DelegationChain;
use crate::errors::CaveatVerificationError;
use crate::Macaroon;

/// Canonical context signed by the delegator when creating a delegated token.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DelegationProofContext {
    pub token_hash: String,
    pub delegated_by: String,
    pub delegated_to: String,
    pub related_rme_id: String,
    pub expires_before: String,
    pub scope_fingerprint: String,
}

impl DelegationProofContext {
    pub fn from_delegation(
        macaroon_token: &str,
        related_rme_id: &str,
        params: &DelegationAttenuationParams,
    ) -> Self {
        Self {
            token_hash: hash_macaroon_token(macaroon_token),
            delegated_by: params.delegated_by.clone(),
            delegated_to: params.delegated_to.clone(),
            related_rme_id: related_rme_id.to_string(),
            expires_before: params
                .expires_before
                .format("%Y-%m-%dT%H:%M:%S")
                .to_string(),
            scope_fingerprint: scope_fingerprint(params),
        }
    }

    /// Reconstruct the exact proof context that a verifier will check from the final token.
    pub fn from_token(macaroon_token: &str) -> Result<Self, CaveatVerificationError> {
        let mac = Macaroon::deserialize(macaroon_token)
            .map_err(|e| CaveatVerificationError::ParseError(e.to_string()))?;
        let parsed = ParsedCaveats::from_macaroon(&mac)?;
        let delegation = DelegationChain::from_parsed(&parsed)?;
        let last_step = delegation.steps.last().ok_or_else(|| {
            CaveatVerificationError::ParseError("No delegation steps found".into())
        })?;

        let scope_payload = format!(
            "r:{}|w:{}|rf:{}|wf:{}",
            last_raw_value(&parsed, CaveatKey::ReadDatasetIn),
            last_raw_value(&parsed, CaveatKey::WriteDatasetIn),
            last_raw_value(&parsed, CaveatKey::ReadFunctionIn),
            last_raw_value(&parsed, CaveatKey::WriteFunctionIn),
        );
        let related_rme_id = parsed
            .all(CaveatKey::RelatedRmeId)
            .last()
            .and_then(|c| match &c.value {
                CaveatValue::Text(value) => Some(value.clone()),
                _ => None,
            })
            .unwrap_or_default();
        let expires_before = last_raw_value(&parsed, CaveatKey::ExpiresBefore);
        if expires_before.is_empty() {
            return Err(CaveatVerificationError::ParseError(
                "Missing expires_before caveat".into(),
            ));
        }

        Ok(Self {
            token_hash: hash_macaroon_token(macaroon_token),
            delegated_by: last_step.delegated_by.clone(),
            delegated_to: last_step.delegated_to.clone(),
            related_rme_id,
            expires_before,
            scope_fingerprint: hex::encode(Sha256::digest(scope_payload.as_bytes())),
        })
    }

    /// Compatibility context for signatures created from the last attenuation params.
    pub fn from_last_delegation_step(macaroon_token: &str) -> Result<Self, CaveatVerificationError> {
        let mac = Macaroon::deserialize(macaroon_token)
            .map_err(|e| CaveatVerificationError::ParseError(e.to_string()))?;
        let parsed = ParsedCaveats::from_macaroon(&mac)?;
        let delegation = DelegationChain::from_parsed(&parsed)?;
        let last_step = delegation.steps.last().ok_or_else(|| {
            CaveatVerificationError::ParseError("No delegation steps found".into())
        })?;
        let step_start = parsed
            .entries
            .iter()
            .rposition(|entry| entry.key == CaveatKey::ParentTokenHash)
            .unwrap_or(0);

        let scope_payload = format!(
            "r:{}|w:{}|rf:{}|wf:{}",
            last_raw_value_from(&parsed, CaveatKey::ReadDatasetIn, step_start),
            last_raw_value_from(&parsed, CaveatKey::WriteDatasetIn, step_start),
            last_raw_value_from(&parsed, CaveatKey::ReadFunctionIn, step_start),
            last_raw_value_from(&parsed, CaveatKey::WriteFunctionIn, step_start),
        );
        let related_rme_id = parsed
            .all(CaveatKey::RelatedRmeId)
            .last()
            .and_then(|c| match &c.value {
                CaveatValue::Text(value) => Some(value.clone()),
                _ => None,
            })
            .unwrap_or_default();
        let expires_before = last_raw_value_from(&parsed, CaveatKey::ExpiresBefore, step_start);
        if expires_before.is_empty() {
            return Err(CaveatVerificationError::ParseError(
                "Missing expires_before caveat".into(),
            ));
        }

        Ok(Self {
            token_hash: hash_macaroon_token(macaroon_token),
            delegated_by: last_step.delegated_by.clone(),
            delegated_to: last_step.delegated_to.clone(),
            related_rme_id,
            expires_before,
            scope_fingerprint: hex::encode(Sha256::digest(scope_payload.as_bytes())),
        })
    }

    pub fn canonical_message(&self) -> Result<String, CaveatVerificationError> {
        serde_json::to_string(self).map_err(|e| CaveatVerificationError::ParseError(e.to_string()))
    }
}

fn last_raw_value(parsed: &ParsedCaveats, key: CaveatKey) -> String {
    parsed
        .all(key)
        .last()
        .and_then(|c| c.raw.split_once('=').map(|(_, v)| v.trim().to_string()))
        .unwrap_or_default()
}

fn last_raw_value_from(parsed: &ParsedCaveats, key: CaveatKey, start: usize) -> String {
    parsed
        .entries
        .iter()
        .skip(start)
        .filter(|c| c.key == key)
        .last()
        .and_then(|c| c.raw.split_once('=').map(|(_, v)| v.trim().to_string()))
        .unwrap_or_default()
}

pub fn hash_macaroon_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn scope_fingerprint(params: &DelegationAttenuationParams) -> String {
    let payload = format!(
        "r:{}|w:{}|rf:{}|wf:{}",
        format_dataset_list(&params.read_datasets),
        format_dataset_list(&params.write_datasets),
        format_function_list(&params.read_functions),
        format_function_list(&params.write_functions),
    );
    hex::encode(Sha256::digest(payload.as_bytes()))
}
