use axum::http::StatusCode;
use decmed_macaroon_auth::{
    attenuate_macaroon, hash_token, issue_initial_token, token_revocation_key,
    verify_decmed_token, AccessMode, CaveatVerificationError, DelegationAttenuationParams,
    DelegationChain, EffectiveCapability, InitialDoctorTokenParams, Macaroon, MacaroonKey,
    ParsedCaveats, SegmentAccessContext, TokenVerificationContext, VerifiedDecmedToken,
    WalletProofContext, WalletSignatureVerifier,
};
use decmed_rme_segment::{
    DatasetCategory, FunctionCategory, RmeSegmentMetadata, SegmentValidationError,
};
use proxy_reencryption::{
    macaroon_auth::verify_segment_for_token, middlewares::ensure_token_not_revoked,
    proxy_error::ProxyError,
};

const PATIENT: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const DOCTOR: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
const LAB: &str = "0x3333333333333333333333333333333333333333333333333333333333333333";
const RME_ID: &str = "RME-001";

struct ActiveActorVerifier {
    active_actor: &'static str,
    valid_sig: &'static str,
}

impl WalletSignatureVerifier for ActiveActorVerifier {
    fn verify(
        &self,
        _context: &WalletProofContext,
        signature_b64: &str,
        expected_address: &str,
    ) -> Result<(), CaveatVerificationError> {
        if expected_address == self.active_actor && signature_b64 == self.valid_sig {
            Ok(())
        } else {
            Err(CaveatVerificationError::InvalidWalletSignature)
        }
    }
}

fn root_key() -> MacaroonKey {
    MacaroonKey::generate(b"decmed-test-root-key-64-bytes-padding!!")
}

fn doctor_token() -> String {
    issue_initial_token(
        &root_key(),
        &InitialDoctorTokenParams::example_doctor_token(PATIENT, RME_ID, DOCTOR),
    )
    .unwrap()
}

fn lab_token() -> String {
    let params = DelegationAttenuationParams {
        delegated_by: DOCTOR.to_string(),
        delegated_to: LAB.to_string(),
        read_datasets: vec![DatasetCategory::LABORATORIUM],
        write_datasets: vec![DatasetCategory::LABORATORIUM],
        read_functions: vec![
            FunctionCategory::ADMINISTRATIVE_GENERAL,
            FunctionCategory::PEMERIKSAAN_PENUNJANG,
            FunctionCategory::LABORATORIUM,
        ],
        write_functions: vec![FunctionCategory::LABORATORIUM],
        expires_before: chrono::DateTime::parse_from_rfc3339("2030-05-16T14:00:00+00:00")
            .unwrap()
            .with_timezone(&chrono::Utc),
        max_delegation_depth: 0,
        related_rme_id: None,
    };
    attenuate_macaroon(&doctor_token(), &params).unwrap()
}

fn verified_read_token() -> (String, Macaroon, VerifiedDecmedToken) {
    let mut params = InitialDoctorTokenParams::example_doctor_token(PATIENT, RME_ID, DOCTOR);
    params.read_datasets = vec![DatasetCategory::RAWAT_JALAN];
    params.read_functions = vec![FunctionCategory::ANAMNESIS];
    let token = issue_initial_token(&root_key(), &params).unwrap();
    let mac = Macaroon::deserialize(&token).unwrap();
    let parsed = ParsedCaveats::from_macaroon(&mac).unwrap();
    let effective = EffectiveCapability::from_parsed(&parsed).unwrap();
    let delegation = DelegationChain::from_parsed(&parsed).unwrap();
    let verified = VerifiedDecmedToken {
        parsed,
        effective,
        delegation,
        token_id: String::from_utf8(mac.identifier().0.clone()).unwrap(),
    };

    (token, mac, verified)
}

fn segment(dataset_category: DatasetCategory, function_category: FunctionCategory) -> RmeSegmentMetadata {
    RmeSegmentMetadata {
        segment_id: "b6c5e2f5-b5a6-41f7-935c-2ec7ccafda31".to_string(),
        related_rme_id: RME_ID.to_string(),
        patient_address: PATIENT.to_string(),
        hospital_cid: "hospital-001".to_string(),
        dataset_category,
        function_category,
        ipfs_cid: "bafy...".to_string(),
        integrity_hash: "hash".to_string(),
        capsule: "capsule".to_string(),
        enc_key_and_nonce: "key".to_string(),
        created_at: "2026-05-18T10:30:00.000Z".to_string(),
        author_address: DOCTOR.to_string(),
        correction_of_index: None,
        correction_reason: None,
        updated_at: None,
    }
}

#[test]
fn pu_ta_07_wallet_proof_must_match_active_actor() {
    let token = lab_token();
    let mac = Macaroon::deserialize(&token).unwrap();
    let verifier = ActiveActorVerifier {
        active_actor: LAB,
        valid_sig: "lab-sig",
    };
    let ctx = TokenVerificationContext {
        operation: AccessMode::Read,
        segment: SegmentAccessContext {
            segment_id: "seg-1".to_string(),
            patient_address: PATIENT.to_string(),
            related_rme_id: RME_ID.to_string(),
            dataset_category: DatasetCategory::LABORATORIUM,
            function_category: FunctionCategory::LABORATORIUM,
        },
        wallet_signature_b64: Some("doctor-sig".to_string()),
        wallet_timestamp: None,
        now: chrono::Utc::now(),
    };

    let err = verify_decmed_token(&mac, &root_key(), &ctx, Some(&verifier)).unwrap_err();
    assert_eq!(err, CaveatVerificationError::InvalidWalletSignature);

    let mut ctx = ctx;
    ctx.wallet_signature_b64 = Some("lab-sig".to_string());
    assert!(verify_decmed_token(&mac, &root_key(), &ctx, Some(&verifier)).is_ok());
}

#[test]
fn pu_ta_08_segment_metadata_requires_valid_dataset_function_category() {
    assert!(segment(DatasetCategory::RAWAT_JALAN, FunctionCategory::ANAMNESIS)
        .validate()
        .is_ok());

    let err = segment(DatasetCategory::APOTEK, FunctionCategory::ANAMNESIS)
        .validate()
        .unwrap_err();
    assert!(matches!(
        err,
        SegmentValidationError::InvalidCategoryCombination { .. }
    ));
}

#[test]
fn pu_ta_09_pre_rejects_segment_outside_caveats_before_reencryption() {
    let (_token, mac, verified) = verified_read_token();
    let outside_scope = segment(DatasetCategory::LABORATORIUM, FunctionCategory::LABORATORIUM);

    let err = verify_segment_for_token(
        &verified,
        &outside_scope,
        AccessMode::Read,
        Some("not-a-real-wallet-signature"),
        &mac,
    )
    .unwrap_err();

    match err {
        ProxyError::Caveat { code, error } => {
            assert_eq!(code, StatusCode::FORBIDDEN.as_u16());
            assert_eq!(
                error,
                CaveatVerificationError::DatasetCategoryNotAllowed.to_string()
            );
        }
        other => panic!("expected caveat denial before wallet/PRE, got {other:?}"),
    }
}

#[test]
fn pu_ta_10_revocation_key_rejects_revoked_token() {
    let (token, _mac, verified) = verified_read_token();
    let revoked_key = token_revocation_key(&hash_token(&token));

    ensure_token_not_revoked(&verified.parsed, &verified.delegation, &token, |_| Ok(false))
        .unwrap();

    let err = ensure_token_not_revoked(&verified.parsed, &verified.delegation, &token, |key| {
        Ok(key == revoked_key)
    })
    .unwrap_err();

    match err {
        ProxyError::Anyhow { source, code } => {
            assert_eq!(code, StatusCode::UNAUTHORIZED);
            assert_eq!(source.to_string(), "Token has been revoked");
        }
        other => panic!("expected revoked token error, got {other:?}"),
    }
}
