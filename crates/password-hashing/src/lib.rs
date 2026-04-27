//! Password hashing using Argon2id
//!
//! OWASP-recommended password hashing with Argon2id algorithm.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

/// Hash a password using Argon2id with a random salt
///
/// # Arguments
/// * `password` - The plaintext password to hash
///
/// # Returns
/// The PHC string format hash, ready for storage
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default(); // Uses Argon2id by default
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Verify a password against a stored hash
///
/// # Arguments
/// * `password` - The plaintext password to verify
/// * `hash` - The stored PHC string format hash
///
/// # Returns
/// `Ok(true)` if password matches, `Ok(false)` if not
pub fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(hash)?;
    let argon2 = Argon2::default();
    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_verify_roundtrip() {
        let password = "my_secure_password_123!";
        let hash = hash_password(password).expect("hashing should succeed");

        // Verify correct password
        assert!(verify_password(password, &hash).expect("verify should succeed"));

        // Reject wrong password
        assert!(!verify_password("wrong_password", &hash).expect("verify should succeed"));
    }

    #[test]
    fn test_hashes_are_unique() {
        let password = "same_password";
        let hash1 = hash_password(password).expect("hashing should succeed");
        let hash2 = hash_password(password).expect("hashing should succeed");

        // Same password produces different hashes (different salts)
        assert_ne!(hash1, hash2);

        // But both verify correctly
        assert!(verify_password(password, &hash1).expect("verify should succeed"));
        assert!(verify_password(password, &hash2).expect("verify should succeed"));
    }

    #[test]
    fn test_empty_password() {
        let password = "";
        let hash = hash_password(password).expect("hashing should succeed");
        assert!(verify_password(password, &hash).expect("verify should succeed"));
    }

    #[test]
    fn test_unicode_password() {
        let password = "my_password_";
        let hash = hash_password(password).expect("hashing should succeed");
        assert!(verify_password(password, &hash).expect("verify should succeed"));
    }
}
