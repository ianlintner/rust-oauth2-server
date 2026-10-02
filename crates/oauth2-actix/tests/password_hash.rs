use argon2::{Argon2, PasswordHash, PasswordVerifier};
use oauth2_actix::handlers::login::hash_password;

#[test]
fn generated_password_hash_verifies_with_fresh_random_salt() {
    // Generate test-only input at runtime; no credential is embedded in this test.
    let password = uuid::Uuid::new_v4().to_string();
    let first = hash_password(&password).expect("hash first password");
    let second = hash_password(&password).expect("hash second password");
    let first = PasswordHash::new(&first).expect("parse first PHC hash");
    let second = PasswordHash::new(&second).expect("parse second PHC hash");
    assert_ne!(
        first.salt, second.salt,
        "each hash needs a fresh random salt"
    );
    Argon2::default()
        .verify_password(password.as_bytes(), &first)
        .expect("correct password verifies");
    assert!(Argon2::default()
        .verify_password(b"incorrect-password", &first)
        .is_err());
}

#[test]
fn pre_upgrade_argon2id_hash_remains_verifiable() {
    // Generated and verified with Argon2 0.5.3 using test-only password "test"
    // and deterministic salt b"oauth2-test-salt"; never used by production.
    let stored = "$argon2id$v=19$m=19456,t=2,p=1$b2F1dGgyLXRlc3Qtc2FsdA$vGORQdc35SoxGDfl6xVl34r9plDoUMBPxC+P20Ri+Ho";
    let parsed = PasswordHash::new(stored).expect("parse persisted PHC hash");
    Argon2::default()
        .verify_password(b"test", &parsed)
        .expect("pre-upgrade stored password verifies");
    assert!(Argon2::default()
        .verify_password(b"incorrect-password", &parsed)
        .is_err());
}
