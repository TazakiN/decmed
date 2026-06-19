use chrono::Utc;
use decmed_rme_segment::{ DatasetCategory, FunctionCategory };
use macaroon::{ Macaroon, MacaroonKey, Verifier };

use crate::caveats::ParsedCaveats;
use crate::delegation::DelegationChain;
use crate::effective::{ AccessMode, EffectiveCapability };
use crate::errors::CaveatVerificationError;
use crate::wallet_proof::{ WalletProofContext, WalletSignatureVerifier };

#[derive(Clone, Debug, PartialEq)]
pub struct SegmentAccessContext {
    pub segment_id: String,
    pub patient_address: String,
    pub related_rme_id: String,
    pub dataset_category: DatasetCategory,
    pub function_category: FunctionCategory,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TokenVerificationContext {
    pub operation: AccessMode,
    pub segment: SegmentAccessContext,
    pub wallet_signature_b64: Option<String>,
    pub wallet_timestamp: Option<String>,
    pub now: chrono::DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct VerifiedDecmedToken {
    pub parsed: ParsedCaveats,
    pub effective: EffectiveCapability,
    pub delegation: DelegationChain,
    pub token_id: String,
    pub is_legacy: bool,
    pub legacy_subject: Option<String>,
    pub legacy_role: Option<String>,
    pub legacy_purpose: Option<String>,
}

pub fn decmed_caveat_satisfier(predicate: &macaroon::ByteString) -> bool {
    if let Ok(pred_str) = String::from_utf8(predicate.0.clone()) {
        if pred_str.starts_with("time < ") {
            return true;
        }
        if let Some((key, _)) = pred_str.split_once('=') {
            return crate::caveats::CaveatKey::from_predicate_key(key.trim()).is_some();
        }
        if pred_str.starts_with("time <") {
            return true;
        }
    }
    false
}

pub fn verify_macaroon_signature(
    mac: &Macaroon,
    root_key: &MacaroonKey
) -> Result<(), CaveatVerificationError> {
    let mut verifier = Verifier::default();
    verifier.satisfy_general(decmed_caveat_satisfier);
    verifier
        .verify(mac, root_key, Default::default())
        .map_err(|_| CaveatVerificationError::InvalidMacaroonSignature)
}

pub fn verify_decmed_token(
    mac: &Macaroon,
    root_key: &MacaroonKey,
    ctx: &TokenVerificationContext,
    wallet_verifier: Option<&dyn WalletSignatureVerifier>
) -> Result<VerifiedDecmedToken, CaveatVerificationError> {
    let parsed = ParsedCaveats::from_macaroon(mac)?;
    if !parsed.is_decmed_token() {
        return verify_legacy_token(mac, root_key, &parsed);
    }

    verify_macaroon_signature(mac, root_key)?;

    let effective = EffectiveCapability::from_parsed(&parsed)?;
    let delegation = DelegationChain::from_parsed(&parsed)?;

    if effective.patient_address.as_deref() != Some(ctx.segment.patient_address.as_str()) {
        return Err(CaveatVerificationError::PatientMismatch);
    }
    match effective.related_rme_id.as_deref() {
        None => {}
        Some(token_rme) if token_rme == ctx.segment.related_rme_id => {}
        Some(_) => {
            return Err(CaveatVerificationError::RmeMismatch);
        }
    }

    if effective.is_expired(ctx.now) {
        return Err(CaveatVerificationError::ExpiredToken);
    }

    if let Some(root_budget) = effective.root_max_delegation_depth {
        let used = delegation.delegation_depth() as u32;
        if used > root_budget {
            return Err(CaveatVerificationError::DelegationDepthExceeded);
        }
    }

    verify_segment_access(&effective, ctx)?;

    let sig = ctx.wallet_signature_b64
        .as_deref()
        .ok_or(CaveatVerificationError::WalletSignatureRequired)?;
    let proof_ctx = WalletProofContext {
        token_id: mac.identifier().to_string(),
        patient_address: ctx.segment.patient_address.clone(),
        related_rme_id: ctx.segment.related_rme_id.clone(),
        operation: ctx.operation,
        segment_id: ctx.segment.segment_id.clone(),
        dataset_category: ctx.segment.dataset_category,
        function_category: ctx.segment.function_category,
        timestamp: ctx.wallet_timestamp.clone().unwrap_or_else(|| ctx.now.to_rfc3339()),
    };
    let verifier = wallet_verifier.ok_or(CaveatVerificationError::InvalidWalletSignature)?;
    verifier.verify(&proof_ctx, sig, &delegation.active_subject)?;

    Ok(VerifiedDecmedToken {
        parsed,
        effective,
        delegation,
        token_id: String::from_utf8(mac.identifier().0.clone()).unwrap_or_default(),
        is_legacy: false,
        legacy_subject: None,
        legacy_role: None,
        legacy_purpose: None,
    })
}

pub fn verify_segment_access(
    effective: &EffectiveCapability,
    ctx: &TokenVerificationContext
) -> Result<(), CaveatVerificationError> {
    let dataset = ctx.segment.dataset_category;
    let function = ctx.segment.function_category;

    let dataset_ok = effective.allows_dataset(ctx.operation, dataset);
    let function_ok = effective.allows_function(ctx.operation, function);

    if !dataset_ok {
        return Err(CaveatVerificationError::DatasetCategoryNotAllowed);
    }
    if !function_ok {
        return Err(CaveatVerificationError::FunctionCategoryNotAllowed);
    }
    Ok(())
}

fn verify_legacy_token(
    mac: &Macaroon,
    root_key: &MacaroonKey,
    parsed: &ParsedCaveats
) -> Result<VerifiedDecmedToken, CaveatVerificationError> {
    use crate::caveats::{ CaveatKey, CaveatValue };

    let subject = parsed
        .all(CaveatKey::Subject)
        .first()
        .and_then(|c| {
            match &c.value {
                CaveatValue::Text(s) => Some(s.clone()),
                _ => None,
            }
        })
        .ok_or(CaveatVerificationError::LegacyTokenIncomplete)?;
    let role = parsed
        .all(CaveatKey::Role)
        .first()
        .and_then(|c| {
            match &c.value {
                CaveatValue::Text(s) => Some(s.clone()),
                _ => None,
            }
        })
        .ok_or(CaveatVerificationError::LegacyTokenIncomplete)?;
    let purpose = parsed
        .all(CaveatKey::Purpose)
        .first()
        .and_then(|c| {
            match &c.value {
                CaveatValue::Text(s) => Some(s.clone()),
                _ => None,
            }
        })
        .ok_or(CaveatVerificationError::LegacyTokenIncomplete)?;

    let mut verifier = Verifier::default();
    verifier.satisfy_exact(format!("subject = {}", subject).into());
    verifier.satisfy_exact(format!("role = {}", role).into());
    verifier.satisfy_exact(format!("purpose = {}", purpose).into());
    verifier.satisfy_general(|pred| {
        if let Ok(pred_str) = String::from_utf8(pred.0.to_vec()) {
            if let Some(time_str) = pred_str.strip_prefix("time < ") {
                if let Ok(exp_time) = time_str.parse::<u64>() {
                    let now = std::time::SystemTime
                        ::now()
                        .duration_since(std::time::SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    return now < exp_time;
                }
            }
        }
        false
    });
    verifier
        .verify(mac, root_key, Default::default())
        .map_err(|_| CaveatVerificationError::InvalidMacaroonSignature)?;

    Ok(VerifiedDecmedToken {
        parsed: parsed.clone(),
        effective: EffectiveCapability {
            read_datasets: Default::default(),
            write_datasets: Default::default(),
            read_functions: Default::default(),
            write_functions: Default::default(),
            expires_before: None,
            root_max_delegation_depth: None,
            remaining_max_delegation_depth: None,
            patient_address: None,
            related_rme_id: None,
            hospital_cid: None,
        },
        delegation: DelegationChain {
            root_subject: subject.clone(),
            steps: vec![],
            active_subject: subject.clone(),
        },
        token_id: String::from_utf8(mac.identifier().0.clone()).unwrap_or_default(),
        is_legacy: true,
        legacy_subject: Some(subject),
        legacy_role: Some(role),
        legacy_purpose: Some(purpose),
    })
}
