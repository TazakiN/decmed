use chrono::Utc;
use decmed_macaroon_auth::{
    admin_write_datasets, admin_write_functions, attenuate_macaroon, compute_revocation_keys,
    edge_revocation_key, hash_token, issue_initial_token, parse_caveat_line,
    root_revocation_key, token_revocation_key, verify_decmed_token, AccessMode, CaveatKey,
    CaveatVerificationError, DelegationAttenuationParams, InitialDoctorTokenParams,
    ParsedCaveats, SegmentAccessContext, TokenVerificationContext, WalletProofContext,
    WalletSignatureVerifier,
};
use decmed_rme_segment::{DatasetCategory, FunctionCategory};
use macaroon::MacaroonKey;

const PATIENT: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const DOCTOR: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
const LAB: &str = "0x3333333333333333333333333333333333333333333333333333333333333333";
const RME_ID: &str = "RME-001";

struct MockVerifier {
    expect_address: Option<String>,
    valid_sig: String,
}

impl WalletSignatureVerifier for MockVerifier {
    fn verify(
        &self,
        _context: &WalletProofContext,
        signature_b64: &str,
        expected_address: &str,
    ) -> Result<(), CaveatVerificationError> {
        if self
            .expect_address
            .as_deref()
            .is_some_and(|a| a != expected_address)
            || signature_b64 != self.valid_sig
        {
            return Err(CaveatVerificationError::InvalidWalletSignature);
        }
        Ok(())
    }
}

fn root_key() -> MacaroonKey {
    MacaroonKey::generate(b"decmed-test-root-key-64-bytes-padding!!")
}

fn doctor_token_params() -> InitialDoctorTokenParams {
    InitialDoctorTokenParams::example_doctor_token(PATIENT, RME_ID, DOCTOR)
}

fn doctor_token() -> String {
    issue_initial_token(&root_key(), &doctor_token_params()).unwrap()
}

fn lab_token(parent: &str) -> String {
    let p = DelegationAttenuationParams {
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
            .with_timezone(&Utc),
        max_delegation_depth: 0,
        related_rme_id: None,
    };
    attenuate_macaroon(parent, &p).unwrap()
}

fn verify_ctx(
    token: &str,
    op: AccessMode,
    dataset: DatasetCategory,
    function: FunctionCategory,
    sig: Option<String>,
    wallet_verifier: Option<&MockVerifier>,
) -> Result<(), CaveatVerificationError> {
    let mac = macaroon::Macaroon::deserialize(token).unwrap();
    let segment = SegmentAccessContext {
        segment_id: "seg-1".into(),
        patient_address: PATIENT.into(),
        related_rme_id: RME_ID.into(),
        dataset_category: dataset,
        function_category: function,
    };
    let ctx = TokenVerificationContext {
        operation: op,
        segment,
        wallet_signature_b64: sig,
        wallet_timestamp: None,
        now: Utc::now(),
    };
    if ctx.wallet_signature_b64.is_none() && wallet_verifier.is_none() {
        let verifier = MockVerifier {
            expect_address: None,
            valid_sig: "valid-sig".into(),
        };
        let mut signed_ctx = ctx;
        signed_ctx.wallet_signature_b64 = Some("valid-sig".into());
        return verify_decmed_token(&mac, &root_key(), &signed_ctx, Some(&verifier)).map(|_| ());
    }

    verify_decmed_token(
        &mac,
        &root_key(),
        &ctx,
        wallet_verifier.map(|v| v as &dyn WalletSignatureVerifier),
    )
    .map(|_| ())
}

#[test]
fn doctor_read_allowed_segment() {
    assert!(verify_ctx(
        &doctor_token(),
        AccessMode::Read,
        DatasetCategory::LABORATORIUM,
        FunctionCategory::LABORATORIUM,
        None,
        None
    )
    .is_ok());
}

const ADMIN: &str = "0x7777777777777777777777777777777777777777777777777777777777777777";

fn admin_read_token() -> String {
    use decmed_macaroon_auth::{
        issue_admin_personnel_token, AdminTokenKind, InitialAdminPersonnelTokenParams,
    };
    let expires = chrono::DateTime::parse_from_rfc3339("2030-05-16T18:00:00+00:00")
        .unwrap()
        .with_timezone(&Utc);
    let params = InitialAdminPersonnelTokenParams::for_grant(
        PATIENT,
        ADMIN,
        DatasetCategory::RAWAT_JALAN,
        AdminTokenKind::Read,
        expires,
    )
    .unwrap();
    issue_admin_personnel_token(&root_key(), &params).unwrap()
}

fn admin_write_token() -> String {
    use decmed_macaroon_auth::{
        issue_admin_personnel_token, AdminTokenKind, InitialAdminPersonnelTokenParams,
    };
    let expires = chrono::DateTime::parse_from_rfc3339("2030-05-16T18:00:00+00:00")
        .unwrap()
        .with_timezone(&Utc);
    let params = InitialAdminPersonnelTokenParams::for_grant(
        PATIENT,
        ADMIN,
        DatasetCategory::RAWAT_JALAN,
        AdminTokenKind::Write,
        expires,
    )
    .unwrap();
    issue_admin_personnel_token(&root_key(), &params).unwrap()
}

fn rm_read_token() -> String {
    let p = InitialDoctorTokenParams::example_rm_initial_token(PATIENT, RME_ID, DOCTOR)
        .into_read_only();
    issue_initial_token(&root_key(), &p).unwrap()
}

fn rm_update_token() -> String {
    let p = InitialDoctorTokenParams::example_rm_initial_token(PATIENT, RME_ID, DOCTOR)
        .into_update_only();
    issue_initial_token(&root_key(), &p).unwrap()
}

#[test]
fn admin_tokens_are_single_purpose_without_role() {
    let read_mac = macaroon::Macaroon::deserialize(&admin_read_token()).unwrap();
    let read_parsed = decmed_macaroon_auth::ParsedCaveats::from_macaroon(&read_mac).unwrap();
    let read_effective =
        decmed_macaroon_auth::EffectiveCapability::from_parsed(&read_parsed).unwrap();
    assert!(!read_effective.read_datasets.is_empty());
    assert!(read_effective.write_datasets.is_empty());

    let write_mac = macaroon::Macaroon::deserialize(&admin_write_token()).unwrap();
    let write_parsed = decmed_macaroon_auth::ParsedCaveats::from_macaroon(&write_mac).unwrap();
    let write_effective =
        decmed_macaroon_auth::EffectiveCapability::from_parsed(&write_parsed).unwrap();
    assert!(write_effective.read_datasets.is_empty());
    assert!(!write_effective.write_datasets.is_empty());
}

#[test]
fn medical_single_purpose_tokens_deny_opposite_mode() {
    let write_err = verify_ctx(
        &rm_read_token(),
        AccessMode::Write,
        DatasetCategory::RAWAT_JALAN,
        FunctionCategory::ANAMNESIS,
        None,
        None,
    )
    .unwrap_err();
    assert_eq!(
        write_err,
        CaveatVerificationError::DatasetCategoryNotAllowed
    );

    let read_err = verify_ctx(
        &rm_update_token(),
        AccessMode::Read,
        DatasetCategory::RAWAT_JALAN,
        FunctionCategory::ANAMNESIS,
        None,
        None,
    )
    .unwrap_err();
    assert_eq!(read_err, CaveatVerificationError::DatasetCategoryNotAllowed);
}

#[test]
fn admin_read_without_rme_reads_any_episode() {
    assert!(verify_ctx(
        &admin_read_token(),
        AccessMode::Read,
        DatasetCategory::RAWAT_INAP,
        FunctionCategory::ANAMNESIS,
        None,
        None
    )
    .is_ok());

    let mac = macaroon::Macaroon::deserialize(&admin_read_token()).unwrap();
    let verifier = MockVerifier {
        expect_address: Some(ADMIN.into()),
        valid_sig: "valid-sig".into(),
    };
    assert!(verify_decmed_token(
        &mac,
        &root_key(),
        &(TokenVerificationContext {
            operation: AccessMode::Read,
            segment: SegmentAccessContext {
                segment_id: "seg".into(),
                patient_address: PATIENT.into(),
                related_rme_id: "RME-OTHER-EPISODE".into(),
                dataset_category: DatasetCategory::LABORATORIUM,
                function_category: FunctionCategory::LABORATORIUM,
            },
            wallet_signature_b64: Some("valid-sig".into()),
            wallet_timestamp: None,
            now: Utc::now(),
        }),
        Some(&verifier)
    )
    .is_ok());
}

#[test]
fn admin_write_parent_assigns_rme_on_delegate() {
    const DELEGATED_RME: &str = "RME-2026-abc12345";
    let datasets = admin_write_datasets(DatasetCategory::RAWAT_JALAN);
    let functions = admin_write_functions(DatasetCategory::RAWAT_JALAN);
    let mut params = DelegationAttenuationParams {
        delegated_by: ADMIN.to_string(),
        delegated_to: DOCTOR.to_string(),
        read_datasets: datasets.clone(),
        write_datasets: datasets,
        read_functions: functions.clone(),
        write_functions: functions,
        expires_before: chrono::DateTime::parse_from_rfc3339("2030-05-16T17:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc),
        max_delegation_depth: 1,
        related_rme_id: Some(DELEGATED_RME.to_string()),
    };
    params.read_datasets.clear();
    params.read_functions.clear();
    let delegated = attenuate_macaroon(&admin_write_token(), &params).unwrap();
    let mac = macaroon::Macaroon::deserialize(&delegated).unwrap();
    let verifier = MockVerifier {
        expect_address: Some(DOCTOR.into()),
        valid_sig: "valid-sig".into(),
    };
    assert!(verify_decmed_token(
        &mac,
        &root_key(),
        &(TokenVerificationContext {
            operation: AccessMode::Write,
            segment: SegmentAccessContext {
                segment_id: "seg-1".into(),
                patient_address: PATIENT.into(),
                related_rme_id: DELEGATED_RME.into(),
                dataset_category: DatasetCategory::RAWAT_JALAN,
                function_category: FunctionCategory::DIAGNOSIS,
            },
            wallet_signature_b64: Some("valid-sig".into()),
            wallet_timestamp: None,
            now: Utc::now(),
        }),
        Some(&verifier)
    )
    .is_ok());

    let rme_err = verify_decmed_token(
        &mac,
        &root_key(),
        &(TokenVerificationContext {
            operation: AccessMode::Write,
            segment: SegmentAccessContext {
                segment_id: "seg".into(),
                patient_address: PATIENT.into(),
                related_rme_id: "RME-WRONG".into(),
                dataset_category: DatasetCategory::RAWAT_JALAN,
                function_category: FunctionCategory::DIAGNOSIS,
            },
            wallet_signature_b64: None,
            wallet_timestamp: None,
            now: Utc::now(),
        }),
        None,
    )
    .unwrap_err();
    assert_eq!(rme_err, CaveatVerificationError::RmeMismatch);
}

#[test]
fn doctor_patient_mismatch() {
    let mac = macaroon::Macaroon::deserialize(&doctor_token()).unwrap();
    let segment = SegmentAccessContext {
        segment_id: "seg".into(),
        patient_address: "0xBAD".into(),
        related_rme_id: RME_ID.into(),
        dataset_category: DatasetCategory::LABORATORIUM,
        function_category: FunctionCategory::LABORATORIUM,
    };
    let err = verify_decmed_token(
        &mac,
        &root_key(),
        &(TokenVerificationContext {
            operation: AccessMode::Read,
            segment,
            wallet_signature_b64: None,
            wallet_timestamp: None,
            now: Utc::now(),
        }),
        None,
    )
    .unwrap_err();
    assert_eq!(err, CaveatVerificationError::PatientMismatch);
}

#[test]
fn doctor_rme_mismatch() {
    let mac = macaroon::Macaroon::deserialize(&doctor_token()).unwrap();
    let segment = SegmentAccessContext {
        segment_id: "seg".into(),
        patient_address: PATIENT.into(),
        related_rme_id: "RME-999".into(),
        dataset_category: DatasetCategory::LABORATORIUM,
        function_category: FunctionCategory::LABORATORIUM,
    };
    let err = verify_decmed_token(
        &mac,
        &root_key(),
        &(TokenVerificationContext {
            operation: AccessMode::Read,
            segment,
            wallet_signature_b64: None,
            wallet_timestamp: None,
            now: Utc::now(),
        }),
        None,
    )
    .unwrap_err();
    assert_eq!(err, CaveatVerificationError::RmeMismatch);
}

#[test]
fn expired_token_rejected() {
    let mac = macaroon::Macaroon::deserialize(&doctor_token()).unwrap();
    let segment = SegmentAccessContext {
        segment_id: "seg".into(),
        patient_address: PATIENT.into(),
        related_rme_id: RME_ID.into(),
        dataset_category: DatasetCategory::LABORATORIUM,
        function_category: FunctionCategory::LABORATORIUM,
    };
    let future = chrono::DateTime::parse_from_rfc3339("2031-01-01T00:00:00+00:00")
        .unwrap()
        .with_timezone(&Utc);
    let err = verify_decmed_token(
        &mac,
        &root_key(),
        &(TokenVerificationContext {
            operation: AccessMode::Read,
            segment,
            wallet_signature_b64: None,
            wallet_timestamp: None,
            now: future,
        }),
        None,
    )
    .unwrap_err();
    assert_eq!(err, CaveatVerificationError::ExpiredToken);
}

#[test]
fn missing_root_subject_rejected() {
    let parsed = ParsedCaveats {
        entries: vec![parse_caveat_line(&format!("patient_address = {PATIENT}")).unwrap()],
    };
    let err = decmed_macaroon_auth::DelegationChain::from_parsed(&parsed).unwrap_err();
    assert_eq!(
        err,
        CaveatVerificationError::MissingRequiredCaveat("root_subject")
    );
}

#[test]
fn lab_read_permintaan_ok() {
    assert!(verify_ctx(
        &lab_token(&doctor_token()),
        AccessMode::Read,
        DatasetCategory::LABORATORIUM,
        FunctionCategory::LABORATORIUM,
        None,
        None
    )
    .is_ok());
}

#[test]
fn lab_write_hasil_ok() {
    assert!(verify_ctx(
        &lab_token(&doctor_token()),
        AccessMode::Write,
        DatasetCategory::LABORATORIUM,
        FunctionCategory::LABORATORIUM,
        None,
        None
    )
    .is_ok());
}

#[test]
fn delegated_token_carries_parent_hash_revocation_key() {
    let parent = doctor_token();
    let child = lab_token(&parent);
    let mac = macaroon::Macaroon::deserialize(&child).unwrap();
    let parsed = ParsedCaveats::from_macaroon(&mac).unwrap();
    let parent_hash = hash_token(&parent);

    let parent_hash_entries = parsed.all(CaveatKey::ParentTokenHash);
    assert_eq!(parent_hash_entries.len(), 1);
    assert!(parent_hash_entries[0].raw.ends_with(&parent_hash));

    let delegation = decmed_macaroon_auth::DelegationChain::from_parsed(&parsed).unwrap();
    let keys = compute_revocation_keys(&parsed, &delegation, &hash_token(&child)).unwrap();
    assert!(keys.contains(&token_revocation_key(&hash_token(&child))));
    assert!(keys.contains(&token_revocation_key(&parent_hash)));
}

#[test]
fn root_revocation_key_blocks_root_and_descendant() {
    let parent = doctor_token();
    let child = lab_token(&parent);
    let expected = root_revocation_key(PATIENT, "Read", DOCTOR);

    for token in [parent, child] {
        let mac = macaroon::Macaroon::deserialize(&token).unwrap();
        let parsed = ParsedCaveats::from_macaroon(&mac).unwrap();
        let delegation = decmed_macaroon_auth::DelegationChain::from_parsed(&parsed).unwrap();
        let keys = compute_revocation_keys(&parsed, &delegation, &hash_token(&token)).unwrap();
        assert!(keys.contains(&expected));
    }
}

#[test]
fn edge_revocation_checks_concrete_and_wildcard_related_rme() {
    let child = lab_token(&doctor_token());
    let mac = macaroon::Macaroon::deserialize(&child).unwrap();
    let parsed = ParsedCaveats::from_macaroon(&mac).unwrap();
    let delegation = decmed_macaroon_auth::DelegationChain::from_parsed(&parsed).unwrap();
    let keys = compute_revocation_keys(&parsed, &delegation, &hash_token(&child)).unwrap();

    assert!(keys.contains(&edge_revocation_key(
        PATIENT,
        "Read",
        DOCTOR,
        LAB,
        Some(RME_ID),
    )));
    assert!(keys.contains(&edge_revocation_key(PATIENT, "Read", DOCTOR, LAB, None)));
}

#[test]
fn lab_read_penunjang_ok() {
    assert!(verify_ctx(
        &lab_token(&doctor_token()),
        AccessMode::Read,
        DatasetCategory::LABORATORIUM,
        FunctionCategory::PEMERIKSAAN_PENUNJANG,
        None,
        None
    )
    .is_ok());
}

#[test]
fn apotek_read_therapy_ok() {
    let p = DelegationAttenuationParams {
        delegated_by: DOCTOR.to_string(),
        delegated_to: LAB.to_string(),
        read_datasets: vec![DatasetCategory::APOTEK],
        write_datasets: vec![DatasetCategory::APOTEK],
        read_functions: vec![
            FunctionCategory::ADMINISTRATIVE_GENERAL,
            FunctionCategory::TERAPI,
            FunctionCategory::PERESEPAN,
            FunctionCategory::DISPENSING,
        ],
        write_functions: vec![FunctionCategory::PERESEPAN, FunctionCategory::DISPENSING],
        expires_before: chrono::DateTime::parse_from_rfc3339("2030-05-16T16:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc),
        max_delegation_depth: 0,
        related_rme_id: None,
    };
    let token = attenuate_macaroon(&doctor_token(), &p).unwrap();
    assert!(verify_ctx(
        &token,
        AccessMode::Read,
        DatasetCategory::APOTEK,
        FunctionCategory::TERAPI,
        None,
        None
    )
    .is_ok());
}

#[test]
fn lab_denied_write_administrative_general() {
    let err = verify_ctx(
        &lab_token(&doctor_token()),
        AccessMode::Write,
        DatasetCategory::LABORATORIUM,
        FunctionCategory::ADMINISTRATIVE_GENERAL,
        None,
        None,
    )
    .unwrap_err();
    assert_eq!(err, CaveatVerificationError::FunctionCategoryNotAllowed);
}

#[test]
fn lab_denied_write_penunjang() {
    let err = verify_ctx(
        &lab_token(&doctor_token()),
        AccessMode::Write,
        DatasetCategory::LABORATORIUM,
        FunctionCategory::PEMERIKSAAN_PENUNJANG,
        None,
        None,
    )
    .unwrap_err();
    assert_eq!(err, CaveatVerificationError::FunctionCategoryNotAllowed);
}

#[test]
fn apotek_denied_write_administrative_general() {
    let p = DelegationAttenuationParams {
        delegated_by: DOCTOR.to_string(),
        delegated_to: LAB.to_string(),
        read_datasets: vec![DatasetCategory::APOTEK],
        write_datasets: vec![DatasetCategory::APOTEK],
        read_functions: vec![
            FunctionCategory::ADMINISTRATIVE_GENERAL,
            FunctionCategory::TERAPI,
            FunctionCategory::PERESEPAN,
            FunctionCategory::DISPENSING,
        ],
        write_functions: vec![FunctionCategory::PERESEPAN, FunctionCategory::DISPENSING],
        expires_before: chrono::DateTime::parse_from_rfc3339("2030-05-16T16:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc),
        max_delegation_depth: 0,
        related_rme_id: None,
    };
    let token = attenuate_macaroon(&doctor_token(), &p).unwrap();
    let err = verify_ctx(
        &token,
        AccessMode::Write,
        DatasetCategory::APOTEK,
        FunctionCategory::ADMINISTRATIVE_GENERAL,
        None,
        None,
    )
    .unwrap_err();
    assert_eq!(err, CaveatVerificationError::FunctionCategoryNotAllowed);
}

#[test]
fn apotek_denied_write_therapy() {
    let p = DelegationAttenuationParams {
        delegated_by: DOCTOR.to_string(),
        delegated_to: LAB.to_string(),
        read_datasets: vec![DatasetCategory::APOTEK],
        write_datasets: vec![DatasetCategory::APOTEK],
        read_functions: vec![
            FunctionCategory::ADMINISTRATIVE_GENERAL,
            FunctionCategory::TERAPI,
            FunctionCategory::PERESEPAN,
            FunctionCategory::DISPENSING,
        ],
        write_functions: vec![FunctionCategory::PERESEPAN, FunctionCategory::DISPENSING],
        expires_before: chrono::DateTime::parse_from_rfc3339("2030-05-16T16:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc),
        max_delegation_depth: 0,
        related_rme_id: None,
    };
    let token = attenuate_macaroon(&doctor_token(), &p).unwrap();
    let err = verify_ctx(
        &token,
        AccessMode::Write,
        DatasetCategory::APOTEK,
        FunctionCategory::TERAPI,
        None,
        None,
    )
    .unwrap_err();
    assert_eq!(err, CaveatVerificationError::FunctionCategoryNotAllowed);
}

#[test]
fn cannot_delegate_write_function_from_parent_read_only_scope() {
    let mut parent_params = doctor_token_params();
    parent_params
        .write_functions
        .retain(|function| *function != FunctionCategory::PERESEPAN);
    let parent = issue_initial_token(&root_key(), &parent_params).unwrap();
    let params = DelegationAttenuationParams {
        delegated_by: DOCTOR.to_string(),
        delegated_to: LAB.to_string(),
        read_datasets: vec![DatasetCategory::APOTEK],
        write_datasets: vec![DatasetCategory::APOTEK],
        read_functions: vec![
            FunctionCategory::ADMINISTRATIVE_GENERAL,
            FunctionCategory::TERAPI,
            FunctionCategory::PERESEPAN,
            FunctionCategory::DISPENSING,
        ],
        write_functions: vec![FunctionCategory::PERESEPAN, FunctionCategory::DISPENSING],
        expires_before: chrono::DateTime::parse_from_rfc3339("2030-05-16T16:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc),
        max_delegation_depth: 0,
        related_rme_id: None,
    };
    let err = attenuate_macaroon(&parent, &params).unwrap_err();
    assert_eq!(
        err,
        CaveatVerificationError::DelegationExpandsAccess("write_function_in".into())
    );
}

#[test]
fn wallet_signature_required_for_every_decmed_token() {
    let token = doctor_token();
    let mac = macaroon::Macaroon::deserialize(&token).unwrap();
    let err = verify_decmed_token(
        &mac,
        &root_key(),
        &TokenVerificationContext {
            operation: AccessMode::Read,
            segment: SegmentAccessContext {
                segment_id: "seg-1".into(),
                patient_address: PATIENT.into(),
                related_rme_id: RME_ID.into(),
                dataset_category: DatasetCategory::LABORATORIUM,
                function_category: FunctionCategory::LABORATORIUM,
            },
            wallet_signature_b64: None,
            wallet_timestamp: None,
            now: Utc::now(),
        },
        None,
    )
    .unwrap_err();
    assert_eq!(err, CaveatVerificationError::WalletSignatureRequired);
}

#[test]
fn invalid_wallet_signature_rejected() {
    let del = DelegationAttenuationParams {
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
            .with_timezone(&Utc),
        max_delegation_depth: 0,
        related_rme_id: None,
    };
    let token = attenuate_macaroon(&doctor_token(), &del).unwrap();
    let verifier = MockVerifier {
        expect_address: Some(LAB.to_string()),
        valid_sig: "valid-sig".into(),
    };
    let err = verify_ctx(
        &token,
        AccessMode::Read,
        DatasetCategory::LABORATORIUM,
        FunctionCategory::LABORATORIUM,
        Some("bad-sig".into()),
        Some(&verifier),
    )
    .unwrap_err();
    assert_eq!(err, CaveatVerificationError::InvalidWalletSignature);

    assert!(verify_ctx(
        &token,
        AccessMode::Read,
        DatasetCategory::LABORATORIUM,
        FunctionCategory::LABORATORIUM,
        Some("valid-sig".into()),
        Some(&verifier)
    )
    .is_ok());
}

#[test]
fn lab_denied_rawat_jalan_diagnosis() {
    let err = verify_ctx(
        &lab_token(&doctor_token()),
        AccessMode::Read,
        DatasetCategory::RAWAT_JALAN,
        FunctionCategory::DIAGNOSIS,
        None,
        None,
    )
    .unwrap_err();
    assert_eq!(err, CaveatVerificationError::DatasetCategoryNotAllowed);
}

#[test]
fn lab_denied_apotek_resep() {
    let err = verify_ctx(
        &lab_token(&doctor_token()),
        AccessMode::Read,
        DatasetCategory::APOTEK,
        FunctionCategory::PERESEPAN,
        None,
        None,
    )
    .unwrap_err();
    assert_eq!(err, CaveatVerificationError::DatasetCategoryNotAllowed);
}

#[test]
fn broken_delegation_chain_rejected() {
    use decmed_macaroon_auth::{add_caveat_to_macaroon, CaveatKey};
    let mut mac = macaroon::Macaroon::deserialize(&doctor_token()).unwrap();
    add_caveat_to_macaroon(&mut mac, CaveatKey::DelegatedBy, "0xAPOTEK");
    add_caveat_to_macaroon(&mut mac, CaveatKey::DelegatedTo, LAB);
    let serialized = mac.serialize(macaroon::Format::V2).unwrap();
    let err = verify_ctx(
        &serialized,
        AccessMode::Read,
        DatasetCategory::LABORATORIUM,
        FunctionCategory::LABORATORIUM,
        None,
        None,
    )
    .unwrap_err();
    assert_eq!(err, CaveatVerificationError::InvalidDelegationChain);
}

#[test]
fn delegated_by_without_to_rejected() {
    use decmed_macaroon_auth::{add_caveat_to_macaroon, CaveatKey};
    let mut mac = macaroon::Macaroon::deserialize(&doctor_token()).unwrap();
    add_caveat_to_macaroon(&mut mac, CaveatKey::DelegatedBy, DOCTOR);
    let mac2 =
        macaroon::Macaroon::deserialize(&mac.serialize(macaroon::Format::V2).unwrap()).unwrap();
    let parsed = decmed_macaroon_auth::ParsedCaveats::from_macaroon(&mac2).unwrap();
    let err = decmed_macaroon_auth::DelegationChain::from_parsed(&parsed).unwrap_err();
    assert_eq!(err, CaveatVerificationError::InvalidDelegationChain);
}

#[test]
fn intersection_blocks_dataset_expansion() {
    let err = verify_ctx(
        &lab_token(&doctor_token()),
        AccessMode::Read,
        DatasetCategory::RAWAT_JALAN,
        FunctionCategory::ANAMNESIS,
        None,
        None,
    )
    .unwrap_err();
    assert_eq!(err, CaveatVerificationError::DatasetCategoryNotAllowed);
}

#[test]
fn cannot_increase_max_delegation_depth_on_delegate() {
    let mut params = DelegationAttenuationParams {
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
            .with_timezone(&Utc),
        max_delegation_depth: 0,
        related_rme_id: None,
    };
    params.max_delegation_depth = 99;
    let err = attenuate_macaroon(&doctor_token(), &params).unwrap_err();
    assert_eq!(err, CaveatVerificationError::DelegationDepthNotMonotonic);
}

#[test]
fn cannot_delegate_when_parent_depth_zero() {
    let mut parent_params = InitialDoctorTokenParams::example_doctor_token(PATIENT, RME_ID, DOCTOR);
    parent_params.max_delegation_depth = 0;
    let parent = issue_initial_token(&root_key(), &parent_params).unwrap();
    let err = attenuate_macaroon(
        &parent,
        &DelegationAttenuationParams {
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
            .with_timezone(&Utc),
        max_delegation_depth: 0,
        related_rme_id: None,
    },
    )
    .unwrap_err();
    assert_eq!(err, CaveatVerificationError::DelegationDepthExceeded);
}

#[test]
fn admin_write_delegates_doctor_preset_succeeds() {
    let datasets = admin_write_datasets(DatasetCategory::RAWAT_JALAN);
    let functions = admin_write_functions(DatasetCategory::RAWAT_JALAN);
    let mut params = DelegationAttenuationParams {
        delegated_by: ADMIN.to_string(),
        delegated_to: DOCTOR.to_string(),
        read_datasets: datasets.clone(),
        write_datasets: datasets,
        read_functions: functions.clone(),
        write_functions: functions,
        expires_before: chrono::DateTime::parse_from_rfc3339("2030-05-16T17:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc),
        max_delegation_depth: 1,
        related_rme_id: Some("RME-DOC-001".to_string()),
    };
    params.read_datasets.clear();
    params.read_functions.clear();
    let delegated = attenuate_macaroon(&admin_write_token(), &params).unwrap();
    let mac = macaroon::Macaroon::deserialize(&delegated).unwrap();
    let parsed = decmed_macaroon_auth::ParsedCaveats::from_macaroon(&mac).unwrap();
    let effective = decmed_macaroon_auth::EffectiveCapability::from_parsed(&parsed).unwrap();
    assert!(effective.read_datasets.is_empty());
    assert!(effective
        .write_datasets
        .contains(&DatasetCategory::RAWAT_JALAN));
    assert!(effective
        .write_datasets
        .contains(&DatasetCategory::LABORATORIUM));
    assert!(effective.write_datasets.contains(&DatasetCategory::APOTEK));
    assert!(!effective
        .write_datasets
        .contains(&DatasetCategory::RAWAT_INAP));
}

#[test]
fn admin_write_seed_token_administrative_general_on_encounter_lab_apotek() {
    const DELEGATED_RME: &str = "RME-2026-seed00001";
    for dataset in [
        DatasetCategory::RAWAT_JALAN,
        DatasetCategory::LABORATORIUM,
        DatasetCategory::APOTEK,
    ] {
        let params = DelegationAttenuationParams {
            delegated_by: ADMIN.to_string(),
            delegated_to: ADMIN.to_string(),
            read_datasets: vec![],
            write_datasets: vec![dataset],
            read_functions: vec![],
            write_functions: vec![FunctionCategory::ADMINISTRATIVE_GENERAL],
            expires_before: chrono::DateTime::parse_from_rfc3339("2030-05-16T18:00:00+00:00")
                .unwrap()
                .with_timezone(&Utc),
            max_delegation_depth: 0,
            related_rme_id: Some(DELEGATED_RME.into()),
        };
        let seed_token = attenuate_macaroon(&admin_write_token(), &params).unwrap();
        let mac = macaroon::Macaroon::deserialize(&seed_token).unwrap();
        let parsed = ParsedCaveats::from_macaroon(&mac).unwrap();
        let effective = decmed_macaroon_auth::EffectiveCapability::from_parsed(&parsed).unwrap();
        assert!(effective.read_datasets.is_empty());
        assert!(effective.read_functions.is_empty());
        assert!(effective
            .write_functions
            .contains(&FunctionCategory::ADMINISTRATIVE_GENERAL));
        let verifier = MockVerifier {
            expect_address: Some(ADMIN.into()),
            valid_sig: "valid-sig".into(),
        };
        assert!(verify_decmed_token(
            &mac,
            &root_key(),
            &(TokenVerificationContext {
                operation: AccessMode::Write,
                segment: SegmentAccessContext {
                    segment_id: "seg-seed".into(),
                    patient_address: PATIENT.into(),
                    related_rme_id: DELEGATED_RME.into(),
                    dataset_category: dataset,
                    function_category: FunctionCategory::ADMINISTRATIVE_GENERAL,
                },
                wallet_signature_b64: Some("valid-sig".into()),
                wallet_timestamp: None,
                now: Utc::now(),
            }),
            Some(&verifier),
        )
        .is_ok());
    }
}

#[test]
fn admin_write_rejects_delegation_with_scope_beyond_write_parent() {
    let params = DelegationAttenuationParams {
        delegated_by: ADMIN.to_string(),
        delegated_to: DOCTOR.to_string(),
        read_datasets: vec![DatasetCategory::RAWAT_INAP],
        write_datasets: vec![DatasetCategory::RAWAT_JALAN],
        read_functions: vec![FunctionCategory::ANAMNESIS],
        write_functions: vec![FunctionCategory::DIAGNOSIS],
        expires_before: chrono::DateTime::parse_from_rfc3339("2030-05-16T18:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc),
        max_delegation_depth: 0,
        related_rme_id: Some("RME-REJECT".into()),
    };
    let err = attenuate_macaroon(&admin_write_token(), &params).unwrap_err();
    assert_eq!(
        err,
        CaveatVerificationError::DelegationExpandsAccess("read_dataset_in".into())
    );
}

#[test]
fn admin_write_true_expansion_still_fails() {
    let params = DelegationAttenuationParams {
        delegated_by: ADMIN.to_string(),
        delegated_to: DOCTOR.to_string(),
        read_datasets: vec![],
        write_datasets: vec![DatasetCategory::RAWAT_INAP],
        read_functions: vec![],
        write_functions: vec![FunctionCategory::DIAGNOSIS],
        expires_before: chrono::DateTime::parse_from_rfc3339("2030-05-16T18:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc),
        max_delegation_depth: 0,
        related_rme_id: Some("RME-EXPAND".into()),
    };
    let err = attenuate_macaroon(&admin_write_token(), &params).unwrap_err();
    assert_eq!(
        err,
        CaveatVerificationError::DelegationExpandsAccess("write_dataset_in".into())
    );
}
