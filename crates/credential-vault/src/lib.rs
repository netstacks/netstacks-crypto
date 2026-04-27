//! Credential Vault
//!
//! Provides AES-256-GCM encryption for at-rest credential storage.
//! Master key is derived from environment variable using Argon2.

mod encryption;
mod keyring;

pub use encryption::{CredentialVault, VaultError};
pub use keyring::{load_master_key, MasterKey};
