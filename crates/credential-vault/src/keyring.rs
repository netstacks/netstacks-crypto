//! Master key management
//!
//! Provides master key derivation from environment variable using Argon2.
//! Each organization gets a unique derived key via per-org salting.

use argon2::Argon2;
use zeroize::Zeroizing;

use super::{CredentialVault, VaultError};

/// Master key wrapper with zeroize on drop
///
/// Not Clone/Copy to prevent accidental key copies in memory.
/// The Zeroizing wrapper ensures the key is cleared from memory on drop.
pub struct MasterKey(Zeroizing<[u8; 32]>);

impl MasterKey {
    /// Derive master key from password and salt using Argon2
    ///
    /// Uses Argon2 default parameters (Argon2id variant).
    /// Salt should be at least 16 bytes for security.
    pub fn derive(password: &[u8], salt: &[u8]) -> Result<Self, VaultError> {
        let mut key = Zeroizing::new([0u8; 32]);

        Argon2::default()
            .hash_password_into(password, salt, key.as_mut())
            .map_err(|_| VaultError::KeyDerivation)?;

        Ok(Self(key))
    }

    /// Create a CredentialVault from this master key
    pub fn create_vault(&self) -> Result<CredentialVault, VaultError> {
        CredentialVault::from_key(&self.0)
    }

    /// Get raw key bytes (use with caution)
    #[cfg(test)]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Load master key from VAULT_MASTER_KEY environment variable
///
/// Salt is derived from org_id for per-organization isolation.
/// This means the same master password gives different keys per org,
/// providing cryptographic isolation between organizations.
///
/// # Errors
/// Returns `VaultError::KeyDerivation` if:
/// - VAULT_MASTER_KEY environment variable is not set
/// - Key derivation fails
pub fn load_master_key(org_id: &uuid::Uuid) -> Result<MasterKey, VaultError> {
    let password =
        std::env::var("VAULT_MASTER_KEY").map_err(|_| VaultError::KeyDerivation)?;

    // Use org_id as salt for per-org key derivation
    // This means same master password gives different keys per org
    let salt = org_id.as_bytes();

    MasterKey::derive(password.as_bytes(), salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_produces_32_byte_key() {
        let password = b"test_password";
        let salt = b"sixteen_byte_salt_here";

        let key = MasterKey::derive(password, salt).unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn derive_is_deterministic() {
        let password = b"test_password";
        let salt = b"sixteen_byte_salt_here";

        let key1 = MasterKey::derive(password, salt).unwrap();
        let key2 = MasterKey::derive(password, salt).unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn different_passwords_produce_different_keys() {
        let salt = b"sixteen_byte_salt_here";

        let key1 = MasterKey::derive(b"password1", salt).unwrap();
        let key2 = MasterKey::derive(b"password2", salt).unwrap();

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn different_salts_produce_different_keys() {
        let password = b"test_password";

        let key1 = MasterKey::derive(password, b"salt_one________").unwrap();
        let key2 = MasterKey::derive(password, b"salt_two________").unwrap();

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn per_org_key_isolation() {
        let org1 = uuid::Uuid::new_v4();
        let org2 = uuid::Uuid::new_v4();
        let password = b"master_password";

        let key1 = MasterKey::derive(password, org1.as_bytes()).unwrap();
        let key2 = MasterKey::derive(password, org2.as_bytes()).unwrap();

        // Same password but different orgs = different keys
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn create_vault_from_master_key() {
        let key = MasterKey::derive(b"password", b"sixteen_byte_salt_here").unwrap();
        let vault = key.create_vault().unwrap();

        // Verify vault works
        let plaintext = b"secret data";
        let encrypted = vault.encrypt(plaintext).unwrap();
        let decrypted = vault.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn load_master_key_requires_env_var() {
        // Ensure env var is not set
        std::env::remove_var("VAULT_MASTER_KEY");

        let org_id = uuid::Uuid::new_v4();
        let result = load_master_key(&org_id);

        assert!(matches!(result, Err(VaultError::KeyDerivation)));
    }

    #[test]
    fn load_master_key_with_env_var() {
        let org_id = uuid::Uuid::new_v4();

        // Set env var temporarily
        std::env::set_var("VAULT_MASTER_KEY", "test_master_password");

        let result = load_master_key(&org_id);

        // Clean up
        std::env::remove_var("VAULT_MASTER_KEY");

        assert!(result.is_ok());
    }
}
