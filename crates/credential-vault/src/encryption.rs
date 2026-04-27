//! AES-256-GCM encryption for credential storage

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};

/// Nonce size for AES-GCM (96 bits / 12 bytes)
const NONCE_SIZE: usize = 12;

/// Errors that can occur during vault operations
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("Key derivation failed")]
    KeyDerivation,

    #[error("Invalid encryption key")]
    InvalidKey,

    #[error("Encryption failed")]
    Encryption,

    #[error("Decryption failed")]
    Decryption,

    #[error("Invalid ciphertext format")]
    InvalidCiphertext,
}

/// Credential vault for encrypting/decrypting secrets using AES-256-GCM
#[derive(Clone)]
pub struct CredentialVault {
    cipher: Aes256Gcm,
}

impl CredentialVault {
    /// Create vault from raw 32-byte key
    pub fn from_key(key: &[u8; 32]) -> Result<Self, VaultError> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| VaultError::InvalidKey)?;
        Ok(Self { cipher })
    }

    /// Encrypt plaintext, returns nonce || ciphertext
    ///
    /// Each call generates a unique random nonce (critical for GCM security).
    /// The nonce is prepended to the ciphertext so decrypt() can extract it.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| VaultError::Encryption)?;

        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data (expects nonce || ciphertext format)
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>, VaultError> {
        if encrypted.len() < NONCE_SIZE {
            return Err(VaultError::InvalidCiphertext);
        }

        let nonce = Nonce::from_slice(&encrypted[..NONCE_SIZE]);
        let ciphertext = &encrypted[NONCE_SIZE..];

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| VaultError::Decryption)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        // Test key - not for production use
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let vault = CredentialVault::from_key(&test_key()).unwrap();
        let plaintext = b"super secret password";

        let encrypted = vault.encrypt(plaintext).unwrap();
        let decrypted = vault.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn unique_nonces_per_encryption() {
        let vault = CredentialVault::from_key(&test_key()).unwrap();
        let plaintext = b"test data";

        let encrypted1 = vault.encrypt(plaintext).unwrap();
        let encrypted2 = vault.encrypt(plaintext).unwrap();

        // Same plaintext should produce different ciphertext (due to unique nonces)
        assert_ne!(encrypted1, encrypted2);

        // Both should decrypt to same plaintext
        assert_eq!(vault.decrypt(&encrypted1).unwrap(), plaintext);
        assert_eq!(vault.decrypt(&encrypted2).unwrap(), plaintext);
    }

    #[test]
    fn decrypt_invalid_ciphertext_too_short() {
        let vault = CredentialVault::from_key(&test_key()).unwrap();

        // Less than NONCE_SIZE bytes
        let result = vault.decrypt(&[0u8; 5]);
        assert!(matches!(result, Err(VaultError::InvalidCiphertext)));
    }

    #[test]
    fn decrypt_tampered_ciphertext() {
        let vault = CredentialVault::from_key(&test_key()).unwrap();
        let plaintext = b"secret";

        let mut encrypted = vault.encrypt(plaintext).unwrap();
        // Tamper with the ciphertext (not the nonce)
        if encrypted.len() > 12 {
            encrypted[12] ^= 0xff;
        }

        let result = vault.decrypt(&encrypted);
        assert!(matches!(result, Err(VaultError::Decryption)));
    }

    #[test]
    fn encrypt_empty_plaintext() {
        let vault = CredentialVault::from_key(&test_key()).unwrap();
        let plaintext = b"";

        let encrypted = vault.encrypt(plaintext).unwrap();
        let decrypted = vault.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_large_plaintext() {
        let vault = CredentialVault::from_key(&test_key()).unwrap();
        let plaintext = vec![0xab; 10000]; // 10KB

        let encrypted = vault.encrypt(&plaintext).unwrap();
        let decrypted = vault.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
