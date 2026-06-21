use decmed_macaroon_auth::{Macaroon, MacaroonKey};
use umbral_pre::{
    decrypt_original, decrypt_reencrypted, encrypt, generate_kfrags, reencrypt, SecretKey, Signer,
};

use crate::utils::Utils;

#[test]
fn test_macaroon_root_key_generation_matches_parser() {
    let generated_key = Utils::generate_macaroon_root_key();
    let parsed_key = Utils::parse_macaroon_root_key(&generated_key).unwrap();

    assert_eq!(generated_key.len(), 128);
    assert_eq!(parsed_key.len(), 64);
}

#[test]
fn test_admin_dual_token_issue_and_verify() {
    use decmed_macaroon_auth::{
        issue_admin_personnel_token, verify_decmed_token, AccessMode, AdminTokenKind,
        InitialAdminPersonnelTokenParams, SegmentAccessContext, TokenVerificationContext,
    };
    use decmed_rme_segment::{DatasetCategory, FunctionCategory};

    const ROOT: &str = "decmed-proxy-test-root-key-64-bytes-padding!!";
    const PATIENT: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
    const ADMIN: &str = "0x7777777777777777777777777777777777777777777777777777777777777777";

    let root_key = MacaroonKey::generate(ROOT.as_bytes());
    let expires = chrono::Utc::now() + chrono::Duration::hours(24);

    let read_params = InitialAdminPersonnelTokenParams::for_grant(
        PATIENT,
        ADMIN,
        DatasetCategory::RAWAT_JALAN,
        AdminTokenKind::Read,
        expires,
    )
    .unwrap();
    let read_token = issue_admin_personnel_token(&root_key, &read_params).unwrap();

    let write_expires = chrono::Utc::now() + chrono::Duration::hours(2);
    let write_params = InitialAdminPersonnelTokenParams::for_grant(
        PATIENT,
        ADMIN,
        DatasetCategory::RAWAT_JALAN,
        AdminTokenKind::Write,
        write_expires,
    )
    .unwrap();
    let write_token = issue_admin_personnel_token(&root_key, &write_params).unwrap();

    struct TestWalletVerifier;
    impl decmed_macaroon_auth::WalletSignatureVerifier for TestWalletVerifier {
        fn verify(
            &self,
            _context: &decmed_macaroon_auth::WalletProofContext,
            signature_b64: &str,
            expected_address: &str,
        ) -> Result<(), decmed_macaroon_auth::CaveatVerificationError> {
            if signature_b64 == "valid-sig" && expected_address == ADMIN {
                Ok(())
            } else {
                Err(decmed_macaroon_auth::CaveatVerificationError::InvalidWalletSignature)
            }
        }
    }
    let wallet_verifier = TestWalletVerifier;

    let read_mac = Macaroon::deserialize(&read_token).unwrap();
    assert!(verify_decmed_token(
        &read_mac,
        &root_key,
        &(TokenVerificationContext {
            operation: AccessMode::Read,
            segment: SegmentAccessContext {
                segment_id: "seg".into(),
                patient_address: PATIENT.into(),
                related_rme_id: "RME-ANY".into(),
                dataset_category: DatasetCategory::RAWAT_INAP,
                function_category: FunctionCategory::ANAMNESIS,
            },
            wallet_signature_b64: Some("valid-sig".into()),
            wallet_timestamp: None,
            now: chrono::Utc::now(),
        }),
        Some(&wallet_verifier)
    )
    .is_ok());

    let write_mac = Macaroon::deserialize(&write_token).unwrap();
    assert!(verify_decmed_token(
        &write_mac,
        &root_key,
        &(TokenVerificationContext {
            operation: AccessMode::Write,
            segment: SegmentAccessContext {
                segment_id: "seg".into(),
                patient_address: PATIENT.into(),
                related_rme_id: "ignored".into(),
                dataset_category: DatasetCategory::LABORATORIUM,
                function_category: FunctionCategory::LABORATORIUM,
            },
            wallet_signature_b64: Some("valid-sig".into()),
            wallet_timestamp: None,
            now: chrono::Utc::now(),
        }),
        Some(&wallet_verifier)
    )
    .is_ok());

    assert!(verify_decmed_token(
        &write_mac,
        &root_key,
        &(TokenVerificationContext {
            operation: AccessMode::Write,
            segment: SegmentAccessContext {
                segment_id: "seg".into(),
                patient_address: PATIENT.into(),
                related_rme_id: "ignored".into(),
                dataset_category: DatasetCategory::RAWAT_INAP,
                function_category: FunctionCategory::ANAMNESIS,
            },
            wallet_signature_b64: None,
            wallet_timestamp: None,
            now: chrono::Utc::now(),
        }),
        None
    )
    .is_err());
}

#[test]
fn test_pre_flow() {
    // 1. Setup Alice (Data Owner) and Bob (Data Consumer)
    let alice_sk = SecretKey::random();
    let alice_pk = alice_sk.public_key();

    let bob_sk = SecretKey::random();
    let bob_pk = bob_sk.public_key();

    let signer_sk = SecretKey::random();
    let signer = Signer::new(signer_sk);

    // 2. Alice encrypts data
    let plaintext = b"Proxy Re-Encryption Test Data";
    let (capsule, ciphertext) = encrypt(&alice_pk, plaintext).unwrap();

    // Alice can decrypt her own data
    let decrypted_by_alice = decrypt_original(&alice_sk, &capsule, &ciphertext).unwrap();
    assert_eq!(plaintext.as_slice(), decrypted_by_alice.as_ref());

    // 3. Alice generates kFrags to delegate access to Bob
    let kfrags = generate_kfrags(&alice_sk, &bob_pk, &signer, 1, 1, true, true);
    let verified_kfrag = kfrags[0].clone();

    // 4. Proxy (PRE Server) re-encrypts the capsule for Bob
    let verified_cfrag = reencrypt(&capsule, verified_kfrag);

    // 5. Bob decrypts the data using the cFrag and the capsule
    let decrypted_by_bob = decrypt_reencrypted(
        &bob_sk,
        &alice_pk,
        &capsule,
        vec![verified_cfrag],
        &ciphertext,
    )
    .unwrap();
    assert_eq!(
        plaintext.as_slice(),
        decrypted_by_bob.as_ref(),
        "Decrypted data by Bob should match the original plaintext"
    );
}
