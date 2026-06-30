use sha2::{Digest, Sha256};

use crate::caveats::{CaveatKey, CaveatValue, ParsedCaveats};
use crate::delegation::DelegationChain;
use crate::errors::CaveatVerificationError;

/// Hash a serialized macaroon token for exact-match revocation.
pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Compute the exact token hash key: `revoked:token:<token_hash>`.
pub fn token_revocation_key(token_hash: &str) -> String {
    format!("revoked:token:{token_hash}")
}

/// Compute exact token revocation keys for the presented token and its ancestors.
pub fn compute_revocation_keys(
    parsed: &ParsedCaveats,
    _delegation: &DelegationChain,
    token_hash: &str,
) -> Result<Vec<String>, CaveatVerificationError> {
    let mut keys = vec![token_revocation_key(token_hash)];
    for parent_hash in parsed.all(CaveatKey::ParentTokenHash) {
        if let CaveatValue::Text(hash) = &parent_hash.value {
            keys.push(token_revocation_key(hash));
        }
    }

    keys.dedup();
    Ok(keys)
}
