# netstacks-credential-vault

AES-256-GCM credential vault with Argon2id key derivation, used by [NetStacks](https://netstacks.net) to encrypt secrets at rest (SSH private keys, API tokens, credentials).

## Usage

### Encrypt with a derived master key

```rust
use netstacks_credential_vault::MasterKey;

// Derive a master key from a password and a salt (e.g., a tenant UUID).
let master_key = MasterKey::derive(b"correct horse battery staple", b"sixteen_byte_salt_here")?;
let vault = master_key.create_vault()?;

let encrypted = vault.encrypt(b"super secret api token")?;
let decrypted = vault.decrypt(&encrypted)?;

assert_eq!(decrypted, b"super secret api token");
```

### Encrypt with a raw key

```rust
use netstacks_credential_vault::CredentialVault;

let key: [u8; 32] = /* obtained from KMS, env var, etc. */;
let vault = CredentialVault::from_key(&key)?;
let encrypted = vault.encrypt(b"secret")?;
```

### Load the master key from `VAULT_MASTER_KEY`

```rust
use netstacks_credential_vault::load_master_key;

let org_id = uuid::Uuid::parse_str("...")?;
let master_key = load_master_key(&org_id)?; // reads VAULT_MASTER_KEY env var
let vault = master_key.create_vault()?;
```

The org UUID is used as a salt, so the same master password produces a different key for every org — providing cryptographic isolation between tenants.

## What it does

- **AES-256-GCM** authenticated encryption for ciphertext (resists tampering).
- **Argon2id** key derivation from passwords (OWASP recommended).
- **Random nonce per encryption** (critical for GCM security).
- **`Zeroizing` master key** — the 32-byte key is wiped from memory on drop.
- **Self-contained ciphertext format** — `nonce || ciphertext`, no external metadata required.

## What it does not do

- It does **not** persist anything. Storage (database, file, etc.) is the caller's responsibility.
- It does **not** rotate keys. If you need key rotation, decrypt with the old key, re-encrypt with the new one.
- It does **not** authenticate the caller. Anyone with the key can decrypt.
- It does **not** protect against memory inspection of running processes — `Zeroizing` only helps after the key is dropped.

## License

MIT — see the [repository LICENSE](../../LICENSE).
