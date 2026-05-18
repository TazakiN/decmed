use std::time::SystemTime;

use macaroon::{Macaroon, MacaroonKey, Verifier};
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
fn test_macaroon_flow() {
    // 1. Generate Root Key
    let root_key_str = "super-secret-root-key-for-testing";
    let root_key = MacaroonKey::generate(root_key_str.as_bytes());

    // 2. Create a Macaroon
    let mut mac = Macaroon::create(
        Some("proxy-reencryption".into()),
        &root_key,
        "test-subject-123".into(),
    )
    .unwrap();

    let future_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;

    mac.add_first_party_caveat("role = MedicalPersonnel".into());
    mac.add_first_party_caveat("purpose = Read".into());
    mac.add_first_party_caveat("subject = test-subject-123".into());
    mac.add_first_party_caveat(format!("time < {}", future_time).into());

    // Serialize
    let serialized_mac = mac.serialize(macaroon::Format::V2).unwrap();

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
    let past_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 1000;
    let mut mac_expired = Macaroon::create(
        Some("proxy-reencryption".into()),
        &root_key,
        "test-subject-123".into(),
    )
    .unwrap();
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

    let verify_expired_result =
        verifier_expired.verify(&mac_expired, &root_key, Default::default());
    assert!(
        verify_expired_result.is_err(),
        "Expired macaroon should fail verification"
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
        &ciphertext,
    )
    .unwrap();
    assert_eq!(
        plaintext.as_slice(),
        decrypted_by_bob.as_ref(),
        "Decrypted data by Bob should match the original plaintext"
    );
}
