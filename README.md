# netstacks-crypto

Open-source cryptographic primitives extracted from [NetStacks](https://netstacks.net), an enterprise network operations platform.

These crates exist so users and security auditors can review exactly how NetStacks protects their secrets — passwords, SSH keys, API tokens, and other credentials.

## Crates

| Crate | Purpose | Algorithm |
|---|---|---|
| [`password-hashing`](crates/password-hashing) | Hash and verify user passwords | Argon2id (OWASP recommended) |
| [`credential-vault`](crates/credential-vault) | Encrypt secrets at rest (databases, local SQLite) | AES-256-GCM + Argon2id key derivation |

Both crates are deliberately small, focused, and dependency-light. They are **not** general-purpose cryptography libraries — they implement specific patterns NetStacks uses in production.

## Where they're used in NetStacks

- **`netstacks-credential-vault`** is consumed by both halves of the platform:
  - The **Controller** (enterprise PostgreSQL backend) — encrypts SSH CA private keys, API tokens, LDAP bind passwords.
  - The **Terminal agent** (standalone/desktop SQLite) — encrypts SSH key passphrases, profile credentials, and integration tokens stored locally.
- **`netstacks-password-hashing`** is used by the Controller for local user account passwords (LDAP/OIDC fallback).

Auditing these two crates therefore covers every place NetStacks derives or applies symmetric encryption to user secrets.

## Why open source?

Cryptographic code is the kind of thing you should not have to take on faith. Publishing these primitives means:

- **Customers can audit them** before trusting NetStacks with credentials.
- **Security researchers can review** the algorithms, parameters, and implementation.
- **Bugs and weaknesses are visible**, which makes them more likely to be found and fixed.

The closed-source NetStacks platform depends on these exact crates — there is no separate "open" and "closed" version of the crypto.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability disclosure.

## License

MIT — see [LICENSE](LICENSE).
