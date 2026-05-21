use chrono::Utc;
use decmed_macaroon_auth::{
    attenuate_macaroon, issue_initial_token, parse_caveat_line, verify_decmed_token, AccessMode,
    CaveatVerificationError, DelegationAttenuationParams, InitialDoctorTokenParams, ParsedCaveats,
    SegmentAccessContext, TokenVerificationContext, WalletProofContext, WalletSignatureVerifier,
};
use decmed_rme_segment::{DatasetCategory, FunctionCategory};
use macaroon::MacaroonKey;

const PATIENT: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const DOCTOR: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
const LAB: &str = "0x3333333333333333333333333333333333333333333333333333333333333333";
const RME_ID: &str = "RME-001";

struct MockVerifier {
    expect_address: String,
    valid_sig: String,
}

impl WalletSignatureVerifier for MockVerifier {
    fn verify(
        &self,
        _context: &WalletProofContext,
        signature_b64: &str,
        expected_address: &str,
    ) -> Result<(), CaveatVerificationError> {
        if expected_address != self.expect_address || signature_b64 != self.valid_sig {
            return Err(CaveatVerificationError::InvalidWalletSignature);
        }
        Ok(())
    }
}

fn root_key() -> MacaroonKey {
    MacaroonKey::generate(b"decmed-test-root-key-64-bytes-padding!!")
}

fn doctor_token_params() -> InitialDoctorTokenParams {
    let mut p = InitialDoctorTokenParams::example_doctor_token(PATIENT, RME_ID, DOCTOR);
    p.require_wallet_proof = false;
    p
}

fn doctor_token() -> String {
    issue_initial_token(&root_key(), &doctor_token_params()).unwrap()
}

fn lab_token(parent: &str) -> String {
    let mut p = DelegationAttenuationParams::example_lab_delegation(DOCTOR, LAB);
    p.require_wallet_proof = false;
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
    verify_decmed_token(
        &mac,
        &root_key(),
        &TokenVerificationContext {
            operation: op,
            segment,
            wallet_signature_b64: sig,
            now: Utc::now(),
        },
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
        FunctionCategory::PERMINTAAN_PEMERIKSAAN,
        None,
        None,
    )
    .is_ok());
}

#[test]
fn doctor_patient_mismatch() {
    let mac = macaroon::Macaroon::deserialize(&doctor_token()).unwrap();
    let segment = SegmentAccessContext {
        segment_id: "seg".into(),
        patient_address: "0xBAD".into(),
        related_rme_id: RME_ID.into(),
        dataset_category: DatasetCategory::LABORATORIUM,
        function_category: FunctionCategory::PERMINTAAN_PEMERIKSAAN,
    };
    let err = verify_decmed_token(
        &mac,
        &root_key(),
        &TokenVerificationContext {
            operation: AccessMode::Read,
            segment,
            wallet_signature_b64: None,
            now: Utc::now(),
        },
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
        function_category: FunctionCategory::PERMINTAAN_PEMERIKSAAN,
    };
    let err = verify_decmed_token(
        &mac,
        &root_key(),
        &TokenVerificationContext {
            operation: AccessMode::Read,
            segment,
            wallet_signature_b64: None,
            now: Utc::now(),
        },
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
        function_category: FunctionCategory::PERMINTAAN_PEMERIKSAAN,
    };
    let future = chrono::DateTime::parse_from_rfc3339("2031-01-01T00:00:00+00:00")
        .unwrap()
        .with_timezone(&Utc);
    let err = verify_decmed_token(
        &mac,
        &root_key(),
        &TokenVerificationContext {
            operation: AccessMode::Read,
            segment,
            wallet_signature_b64: None,
            now: future,
        },
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
        FunctionCategory::PERMINTAAN_PEMERIKSAAN,
        None,
        None,
    )
    .is_ok());
}

#[test]
fn lab_write_hasil_ok() {
    assert!(verify_ctx(
        &lab_token(&doctor_token()),
        AccessMode::Write,
        DatasetCategory::LABORATORIUM,
        FunctionCategory::HASIL_PEMERIKSAAN,
        None,
        None,
    )
    .is_ok());
}

#[test]
fn wallet_signature_required_when_proof_caveat_present() {
    let mut p = doctor_token_params();
    p.require_wallet_proof = true;
    let token = issue_initial_token(&root_key(), &p).unwrap();
    let err = verify_ctx(
        &token,
        AccessMode::Read,
        DatasetCategory::LABORATORIUM,
        FunctionCategory::PERMINTAAN_PEMERIKSAAN,
        None,
        None,
    )
    .unwrap_err();
    assert_eq!(err, CaveatVerificationError::WalletSignatureRequired);
}

#[test]
fn invalid_wallet_signature_rejected() {
    let mut del = DelegationAttenuationParams::example_lab_delegation(DOCTOR, LAB);
    del.require_wallet_proof = true;
    let token = attenuate_macaroon(&doctor_token(), &del).unwrap();
    let verifier = MockVerifier {
        expect_address: LAB.to_string(),
        valid_sig: "valid-sig".into(),
    };
    let err = verify_ctx(
        &token,
        AccessMode::Read,
        DatasetCategory::LABORATORIUM,
        FunctionCategory::PERMINTAAN_PEMERIKSAAN,
        Some("bad-sig".into()),
        Some(&verifier),
    )
    .unwrap_err();
    assert_eq!(err, CaveatVerificationError::InvalidWalletSignature);

    assert!(verify_ctx(
        &token,
        AccessMode::Read,
        DatasetCategory::LABORATORIUM,
        FunctionCategory::PERMINTAAN_PEMERIKSAAN,
        Some("valid-sig".into()),
        Some(&verifier),
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
        FunctionCategory::DATA_RESEP_DAN_OBAT,
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
        FunctionCategory::PERMINTAAN_PEMERIKSAAN,
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
    let mac2 = macaroon::Macaroon::deserialize(&mac.serialize(macaroon::Format::V2).unwrap()).unwrap();
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
    let mut params = DelegationAttenuationParams::example_lab_delegation(DOCTOR, LAB);
    params.max_delegation_depth = 99;
    let err = attenuate_macaroon(&doctor_token(), &params).unwrap_err();
    assert_eq!(
        err,
        CaveatVerificationError::DelegationDepthNotMonotonic
    );
}

#[test]
fn cannot_delegate_when_parent_depth_zero() {
    let mut parent_params = InitialDoctorTokenParams::example_doctor_token(PATIENT, RME_ID, DOCTOR);
    parent_params.max_delegation_depth = 0;
    let parent = issue_initial_token(&root_key(), &parent_params).unwrap();
    let err = attenuate_macaroon(
        &parent,
        &DelegationAttenuationParams::example_lab_delegation(DOCTOR, LAB),
    )
    .unwrap_err();
    assert_eq!(err, CaveatVerificationError::DelegationDepthExceeded);
}

#[test]
fn holder_address_forbidden() {
    use decmed_macaroon_auth::parse_caveat_line;
    let err = parse_caveat_line("holder_address = 0x1").unwrap_err();
    assert_eq!(err, CaveatVerificationError::HolderAddressForbidden);
}
