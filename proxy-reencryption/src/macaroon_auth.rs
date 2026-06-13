use axum::http::StatusCode;
use decmed_macaroon_auth::{
    verify_decmed_token, verify_segment_access, AccessMode, CaveatVerificationError,
    SegmentAccessContext, TokenVerificationContext, VerifiedDecmedToken, WalletProofContext,
    WalletSignatureVerifier,
};
use decmed_rme_segment::RmeSegmentMetadata;
use iota_types::base_types::IotaAddress;
use iota_types::crypto::{IotaSignature, SignatureScheme};
use macaroon::{Macaroon, MacaroonKey};
use shared_crypto::intent::{Intent, IntentMessage};
use std::str::FromStr;

use crate::proxy_error::ProxyError;

pub struct IotaWalletVerifier;

impl WalletSignatureVerifier for IotaWalletVerifier {
    fn verify(
        &self,
        context: &WalletProofContext,
        signature_b64: &str,
        expected_address: &str,
    ) -> Result<(), CaveatVerificationError> {
        let address = IotaAddress::from_str(expected_address)
            .map_err(|_| CaveatVerificationError::InvalidWalletSignature)?;
        let message = context.canonical_message()?;
        let intent_message = IntentMessage::new(Intent::personal_message(), message);
        let signature = crate::utils::Utils::construct_signature_from_str(signature_b64)
            .map_err(|_| CaveatVerificationError::InvalidWalletSignature)?;
        signature
            .verify_secure(&intent_message, address, SignatureScheme::ED25519)
            .map_err(|_| CaveatVerificationError::InvalidWalletSignature)?;
        Ok(())
    }
}

pub fn caveat_error_to_status(err: &CaveatVerificationError) -> StatusCode {
    match err {
        CaveatVerificationError::InvalidMacaroonSignature => StatusCode::UNAUTHORIZED,
        CaveatVerificationError::MissingRequiredCaveat(_)
        | CaveatVerificationError::LegacyTokenIncomplete => StatusCode::UNAUTHORIZED,
        CaveatVerificationError::PatientMismatch | CaveatVerificationError::RmeMismatch => {
            StatusCode::FORBIDDEN
        }
        CaveatVerificationError::ExpiredToken => StatusCode::UNAUTHORIZED,
        CaveatVerificationError::RevokedToken => StatusCode::UNAUTHORIZED,
        CaveatVerificationError::InvalidDelegationChain
        | CaveatVerificationError::DelegationDepthExceeded
        | CaveatVerificationError::DelegationDepthNotMonotonic => StatusCode::FORBIDDEN,
        CaveatVerificationError::WalletSignatureRequired
        | CaveatVerificationError::InvalidWalletSignature => StatusCode::UNAUTHORIZED,
        CaveatVerificationError::DatasetCategoryNotAllowed
        | CaveatVerificationError::FunctionCategoryNotAllowed => StatusCode::FORBIDDEN,
        _ => StatusCode::BAD_REQUEST,
    }
}

pub fn map_caveat_error(err: CaveatVerificationError) -> ProxyError {
    let code = caveat_error_to_status(&err);
    ProxyError::Caveat {
        code: code.as_u16(),
        error: err.to_string(),
    }
}

pub fn verify_segment_for_token(
    verified: &VerifiedDecmedToken,
    metadata: &RmeSegmentMetadata,
    operation: AccessMode,
    wallet_signature: Option<&str>,
    mac: &Macaroon,
) -> Result<(), ProxyError> {
    let segment = SegmentAccessContext {
        segment_id: metadata.segment_id.clone(),
        patient_address: metadata.patient_address.clone(),
        related_rme_id: metadata.related_rme_id.clone(),
        dataset_category: metadata.dataset_category,
        function_category: metadata.function_category,
    };
    let ctx = TokenVerificationContext {
        operation,
        segment,
        wallet_signature_b64: wallet_signature.map(|s| s.to_string()),
        wallet_timestamp: None,
        now: chrono::Utc::now(),
    };
    verify_segment_access(&verified.effective, &ctx).map_err(map_caveat_error)?;
    let sig = wallet_signature
        .ok_or_else(|| map_caveat_error(CaveatVerificationError::WalletSignatureRequired))?;
    let proof_ctx = WalletProofContext {
        token_id: String::from_utf8(mac.identifier().0.clone()).unwrap_or_default(),
        patient_address: metadata.patient_address.clone(),
        related_rme_id: metadata.related_rme_id.clone(),
        operation,
        segment_id: metadata.segment_id.clone(),
        dataset_category: metadata.dataset_category,
        function_category: metadata.function_category,
        timestamp: ctx.now.to_rfc3339(),
    };
    IotaWalletVerifier
        .verify(&proof_ctx, sig, &verified.delegation.active_subject)
        .map_err(map_caveat_error)?;
    Ok(())
}

pub fn verify_decmed_macaroon(
    mac: &Macaroon,
    root_key: &MacaroonKey,
    patient_address: &str,
    related_rme_id: &str,
    operation: AccessMode,
    segment: Option<SegmentAccessContext>,
    wallet_signature: Option<&str>,
) -> Result<VerifiedDecmedToken, ProxyError> {
    let segment = segment.unwrap_or(SegmentAccessContext {
        segment_id: String::new(),
        patient_address: patient_address.to_string(),
        related_rme_id: related_rme_id.to_string(),
        dataset_category: decmed_rme_segment::DatasetCategory::RAWAT_JALAN,
        function_category: decmed_rme_segment::FunctionCategory::ADMINISTRATIVE_GENERAL,
    });
    let ctx = TokenVerificationContext {
        operation,
        segment,
        wallet_signature_b64: wallet_signature.map(|s| s.to_string()),
        wallet_timestamp: None,
        now: chrono::Utc::now(),
    };
    let verifier: Option<&dyn WalletSignatureVerifier> = if wallet_signature.is_some() {
        Some(&IotaWalletVerifier)
    } else {
        None
    };
    verify_decmed_token(mac, root_key, &ctx, verifier).map_err(map_caveat_error)
}
