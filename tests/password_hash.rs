use oauth2_actix::handlers::login::hash_password;

#[test]
fn password_hash_uses_argon2id_with_fresh_random_salts() {
    // Use the same runtime-generated input twice so only the random salt differs.
    let password = uuid::Uuid::new_v4().to_string();
    let first = hash_password(&password).expect("first password hash");
    let second = hash_password(&password).expect("second password hash");
    let first: Vec<_> = first.split('$').collect();
    let second: Vec<_> = second.split('$').collect();
    assert_eq!(first.len(), 6);
    assert_eq!(second.len(), 6);
    assert_eq!(first[1], "argon2id");
    assert_eq!(first[2], "v=19");
    assert_eq!(first[3], "m=19456,t=2,p=1");
    assert_eq!(first[4].len(), 22, "16-byte salt encoded without padding");
    assert_eq!(first[5].len(), 43, "32-byte hash encoded without padding");
    assert_ne!(first[4], second[4], "each hash needs a fresh random salt");
}
