use decmed_macaroon_auth::{ByteString, Caveat, Format, Macaroon, MacaroonKey, Verifier};

#[test]
fn public_facade_supports_low_level_macaroon_flow() {
    let root_key = MacaroonKey::generate(b"decmed-public-facade-test-key");
    let mut macaroon = Macaroon::create(
        Some("decmed-public-facade".into()),
        &root_key,
        "test-subject".into(),
    )
    .unwrap();
    let caveat: ByteString = "purpose = Read".into();
    macaroon.add_first_party_caveat(caveat);

    let serialized = macaroon.serialize(Format::V2).unwrap();
    let deserialized = Macaroon::deserialize(&serialized).unwrap();

    assert!(deserialized
        .caveats()
        .iter()
        .any(|caveat| matches!(caveat, Caveat::FirstParty(_))));

    let mut verifier = Verifier::default();
    verifier.satisfy_exact("purpose = Read".into());
    verifier
        .verify(&deserialized, &root_key, Default::default())
        .unwrap();
}
