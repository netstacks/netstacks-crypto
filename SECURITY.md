# Security Policy

## Reporting a Vulnerability

If you find a security issue in any crate in this repository, **please do not open a public GitHub issue.**

Instead, email **security@netstacks.net** with:

- A description of the issue
- Steps to reproduce
- Affected crate and version
- Your assessment of impact, if any

We aim to acknowledge reports within 72 hours and to publish a fix or mitigation within 30 days for confirmed vulnerabilities.

## Supported Versions

Only the latest published `0.x` release of each crate receives security updates while these crates are pre-1.0.

## Threat Model

These crates implement specific cryptographic primitives. They assume:

- The host operating system's CSPRNG (`getrandom` / `OsRng`) is trustworthy.
- The caller protects key material in memory beyond what `zeroize` can guarantee (the OS may swap memory, snapshot VMs, etc.).
- The caller chooses appropriate Argon2 parameters for their threat model. The crates use library defaults, which match OWASP recommendations as of the publication date.

These crates do **not** protect against:

- A compromised host with code execution.
- Side-channel attacks on the host (timing, power, cache).
- Misuse of the API (e.g., reusing nonces, storing the master key in plaintext).

## Known Limitations

Each crate documents its own known limitations in its README.
