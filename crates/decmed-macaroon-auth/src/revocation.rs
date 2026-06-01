use sha2::{Digest, Sha256};

use crate::caveats::{CaveatKey, CaveatValue, ParsedCaveats};
use crate::delegation::DelegationChain;
use crate::errors::CaveatVerificationError;

/// Hash a serialized macaroon token for exact-match revocation.
pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Compute the root revocation key: `revoked:root:<patient>:<purpose>:<root_subject>`.
/// Used for legacy cascade when no parent_token_hash exists.
pub fn root_revocation_key(patient_address: &str, purpose: &str, root_subject: &str) -> String {
    format!("revoked:root:{patient_address}:{purpose}:{root_subject}")
}

/// Compute the edge revocation key: `revoked:edge:<patient>:<purpose>:<delegated_by>:<delegated_to>:<related_rme_id|*>`.
/// Used for cascade when any ancestor token is revoked.
pub fn edge_revocation_key(
    patient_address: &str,
    purpose: &str,
    delegated_by: &str,
    delegated_to: &str,
    related_rme_id: Option<&str>,
) -> String {
    let rme = related_rme_id.unwrap_or("*");
    format!("revoked:edge:{patient_address}:{purpose}:{delegated_by}:{delegated_to}:{rme}")
}

/// Compute the exact token hash key: `revoked:token:<token_hash>`.
pub fn token_revocation_key(token_hash: &str) -> String {
    format!("revoked:token:{token_hash}")
}

/// Compute all revocation keys that should be checked for a given token.
pub fn compute_revocation_keys(
    parsed: &ParsedCaveats,
    delegation: &DelegationChain,
    token_hash: &str,
) -> Result<Vec<String>, CaveatVerificationError> {
    let patient_address = single_text(parsed, CaveatKey::PatientAddress)?.ok_or(
        CaveatVerificationError::MissingRequiredCaveat("patient_address"),
    )?;
    let purpose = parsed
        .all(CaveatKey::Purpose)
        .first()
        .and_then(|c| match &c.value {
            CaveatValue::Text(s) => Some(s.clone()),
            _ => None,
        })
        .unwrap_or_else(|| "Read".to_string());

    let mut keys = vec![token_revocation_key(token_hash)];
    for parent_hash in parsed.all(CaveatKey::ParentTokenHash) {
        if let CaveatValue::Text(hash) = &parent_hash.value {
            keys.push(token_revocation_key(hash));
        }
    }

    keys.push(root_revocation_key(
        &patient_address,
        &purpose,
        &delegation.root_subject,
    ));

    let related_rme = single_text(parsed, CaveatKey::RelatedRmeId)?;
    for step in &delegation.steps {
        if let Some(rme_id) = related_rme.as_deref() {
            keys.push(edge_revocation_key(
                &patient_address,
                &purpose,
                &step.delegated_by,
                &step.delegated_to,
                Some(rme_id),
            ));
        }
        keys.push(edge_revocation_key(
            &patient_address,
            &purpose,
            &step.delegated_by,
            &step.delegated_to,
            None,
        ));
    }

    keys.dedup();
    Ok(keys)
}

fn single_text(
    parsed: &ParsedCaveats,
    key: CaveatKey,
) -> Result<Option<String>, CaveatVerificationError> {
    let entries = parsed.all(key);
    if entries.is_empty() {
        return Ok(None);
    }
    if entries.len() != 1 {
        return Err(CaveatVerificationError::ParseError(format!(
            "{key:?} must appear exactly once"
        )));
    }
    match &entries[0].value {
        CaveatValue::Text(s) => Ok(Some(s.clone())),
        _ => Err(CaveatVerificationError::ParseError("text expected".into())),
    }
}
