# netstacks-password-hashing

Argon2id password hashing primitives used by [NetStacks](https://netstacks.net).

This crate is intentionally minimal: two functions, `hash_password` and `verify_password`, both backed by the [`argon2`](https://crates.io/crates/argon2) crate's defaults (Argon2id, OWASP-recommended parameters).

## Usage

```rust
use netstacks_password_hashing::{hash_password, verify_password};

let hash = hash_password("correct horse battery staple")?;

assert!(verify_password("correct horse battery staple", &hash)?);
assert!(!verify_password("wrong password", &hash)?);
```

## What it does

- Generates a cryptographically random salt for every hash.
- Returns hashes in the standard PHC string format (portable across any Argon2 implementation).
- Uses Argon2id (the OWASP-recommended variant — resistant to both side-channel and GPU attacks).
- Uses the `argon2` crate's default parameters, which match OWASP's current minimums.

## What it does not do

- It does **not** implement custom or tunable Argon2 parameters. If your threat model requires different memory/time/parallelism costs, use the [`argon2`](https://crates.io/crates/argon2) crate directly.
- It does **not** rate-limit or lock out repeated verification attempts. That's the caller's responsibility.

## License

MIT — see the [repository LICENSE](../../LICENSE).
