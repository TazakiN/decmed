use std::time::SystemTime;

use decmed_macaroon_auth::{ Format, Macaroon, MacaroonKey, Verifier };
use umbral_pre::{
    decrypt_original,
    decrypt_reencrypted,
    encrypt,
    generate_kfrags,
    reencrypt,
    SecretKey,
    Signer,
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
fn test_macaroon_flow() {
    // 1. Generate Root Key
    let root_key_str = "super-secret-root-key-for-testing";
    let root_key = MacaroonKey::generate(root_key_str.as_bytes());

    // 2. Create a Macaroon
    let mut mac = Macaroon::create(
        Some("proxy-reencryption".into()),
        &root_key,
        "test-subject-123".into()
    ).unwrap();

    let future_time =
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() + 3600;

    mac.add_first_party_caveat("role = MedicalPersonnel".into());
    mac.add_first_party_caveat("purpose = Read".into());
    mac.add_first_party_caveat("subject = test-subject-123".into());
    mac.add_first_party_caveat(format!("time < {}", future_time).into());

    // Serialize
    let serialized_mac = mac.serialize(Format::V2).unwrap();

    // Deserialize
    let deserialized_mac = Macaroon::deserialize(&serialized_mac).unwrap();

    // Verify exactly as in middlewares.rs
    let mut verifier = Verifier::default();
    verifier.satisfy_exact("subject = test-subject-123".into());
    verifier.satisfy_exact("role = MedicalPersonnel".into());
    verifier.satisfy_exact("purpose = Read".into());
    verifier.satisfy_general(|pred| {
        if let Ok(pred_str) = String::from_utf8(pred.0.to_vec()) {
            if let Some(time_str) = pred_str.strip_prefix("time < ") {
                if let Ok(exp_time) = time_str.parse::<u64>() {
                    let now = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    return now < exp_time;
                }
            }
        }
        false
    });

    let verify_result = verifier.verify(&deserialized_mac, &root_key, Default::default());
    assert!(verify_result.is_ok(), "Macaroon verification failed");

    // Test expiration
    let past_time =
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() - 1000;
    let mut mac_expired = Macaroon::create(
        Some("proxy-reencryption".into()),
        &root_key,
        "test-subject-123".into()
    ).unwrap();
    mac_expired.add_first_party_caveat("role = MedicalPersonnel".into());
    mac_expired.add_first_party_caveat("purpose = Read".into());
    mac_expired.add_first_party_caveat("subject = test-subject-123".into());
    mac_expired.add_first_party_caveat(format!("time < {}", past_time).into());

    let mut verifier_expired = Verifier::default();
    verifier_expired.satisfy_exact("subject = test-subject-123".into());
    verifier_expired.satisfy_exact("role = MedicalPersonnel".into());
    verifier_expired.satisfy_exact("purpose = Read".into());
    verifier_expired.satisfy_general(|pred| {
        if let Ok(pred_str) = String::from_utf8(pred.0.to_vec()) {
            if let Some(time_str) = pred_str.strip_prefix("time < ") {
                if let Ok(exp_time) = time_str.parse::<u64>() {
                    let now = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    return now < exp_time;
                }
            }
        }
        false
    });

    let verify_expired_result = verifier_expired.verify(
        &mac_expired,
        &root_key,
        Default::default()
    );
    assert!(verify_expired_result.is_err(), "Expired macaroon should fail verification");
}

#[test]
fn test_admin_dual_token_issue_and_verify() {
    use decmed_macaroon_auth::{
        issue_admin_personnel_token,
        verify_decmed_token,
        AccessMode,
        AdminTokenKind,
        InitialAdminPersonnelTokenParams,
        SegmentAccessContext,
        TokenVerificationContext,
    };
    use decmed_rme_segment::{ DatasetCategory, FunctionCategory };

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
        expires
    ).unwrap();
    let read_token = issue_admin_personnel_token(&root_key, &read_params).unwrap();

    let write_expires = chrono::Utc::now() + chrono::Duration::hours(2);
    let write_params = InitialAdminPersonnelTokenParams::for_grant(
        PATIENT,
        ADMIN,
        DatasetCategory::RAWAT_JALAN,
        AdminTokenKind::Write,
        write_expires
    ).unwrap();
    let write_token = issue_admin_personnel_token(&root_key, &write_params).unwrap();

    struct TestWalletVerifier;
    impl decmed_macaroon_auth::WalletSignatureVerifier for TestWalletVerifier {
        fn verify(
            &self,
            _context: &decmed_macaroon_auth::WalletProofContext,
            signature_b64: &str,
            expected_address: &str
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
    assert!(
        verify_decmed_token(
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
        ).is_ok()
    );

    let write_mac = Macaroon::deserialize(&write_token).unwrap();
    assert!(
        verify_decmed_token(
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
        ).is_ok()
    );

    assert!(
        verify_decmed_token(
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
        ).is_err()
    );
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
        &ciphertext
    ).unwrap();
    assert_eq!(
        plaintext.as_slice(),
        decrypted_by_bob.as_ref(),
        "Decrypted data by Bob should match the original plaintext"
    );
}
