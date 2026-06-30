use decmed_macaroon_auth::{Macaroon, MacaroonKey};

#[test]
fn public_facade_supports_keyed_macaroon_creation() {
    let root_key = MacaroonKey::generate(b"decmed-public-facade-test-key");
    let macaroon = Macaroon::create(
        Some("decmed-public-facade".into()),
        &root_key,
        "test-subject".into(),
    )
    .unwrap();

    assert_eq!(
        String::from_utf8(macaroon.identifier().0.clone()).unwrap(),
        "test-subject"
    );
}
