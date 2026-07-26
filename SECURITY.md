# Security Policy

Mima stores high-value credentials. Treat every deployment, extension build and change to cryptographic code as security-sensitive.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability or include real secrets, recovery shares, private keys, session cookies, database dumps or user data in a report.

Use GitHub's private vulnerability reporting for this repository. Include:

- affected commit or release;
- component and deployment shape;
- reproducible steps using synthetic data;
- expected and observed behavior;
- realistic impact and prerequisites;
- a minimal patch or mitigation, if available.

There is no guaranteed response SLA for this community project. If private reporting is unavailable, open a public issue containing only a request for a private security contact, without disclosing technical details.

## Supported versions

Security fixes are made on the current default branch and may be included in the next release. Older releases are not guaranteed to receive backports. Operators should test updates promptly and retain a verified backup before upgrading.

## Security model

Mima encrypts credential content and its user-facing metadata in the client. The service stores ciphertext, public keys, signatures, authorization relationships and operational metadata.

The service can observe:

- users and external identity mappings;
- personal/team classification, owners, members, groups and roles;
- opaque vault/item IDs, versions, tombstones and timestamps;
- ciphertext sizes, IP addresses, user agents and access patterns.

The service should not receive:

- master passwords or password-derived keys;
- user/device private keys or active vault/content keys;
- plaintext titles, accounts, URLs, notes, folders, tags or credentials;
- plaintext search indexes;
- enterprise recovery shares.

The Web E2EE model still trusts the JavaScript currently served to the browser. It does not protect against a malicious build, XSS, a compromised endpoint, a malicious browser extension, keylogging, screen capture, browser vulnerabilities or an authorized user exporting data. Weak master passwords may be guessed offline. Revocation cannot erase content a former member already viewed or copied.

## Non-negotiable invariants

- Authentication providers identify a user; they never unlock user data.
- Group membership never grants `platform-admin`; the role requires an explicit local assignment.
- A platform administrator does not automatically receive vault keys.
- User groups express authorization sets and never own a shared group key.
- Locking destroys decrypted projections, search indexes and active key material; failures remain locked.
- The API validates authorization, versions, signatures and ciphertext structure but does not implement client decryption.
- Existing database migrations are immutable and protected by `apps/api/src/db/migration-lock.json`.
- Demo authentication requires `MIMA_DEMO_MODE=true` and loopback-only origins.
- Production extension builds require HTTPS and a deployment-specific stable manifest identity.

## Cryptography

The protocol identifier remains `lm-e2ee-v1` for wire compatibility. Its implementation is centralized in `packages/e2ee`.

- Argon2id derives a wrapping key from the master password.
- XChaCha20-Poly1305-IETF encrypts symmetric payloads.
- X25519 sealed boxes create recipient envelopes.
- Ed25519 detached signatures authenticate client operations.
- Random account, vault, content and device keys are wrapped rather than derived from identity-provider credentials.

Do not replace algorithms, parameters, AAD, canonical encoding or envelope formats without a versioned protocol design, compatibility tests and independent review.

## Deployment secrets

`deploy/runtime.env`, `.mima/`, backups and recovery artifacts must never be committed. A complete server recovery requires the database plus runtime keys, audit keys, identity secrets and the stable extension identity. Backups created by `deploy/mima.sh backup` are sensitive and are not additionally encrypted by the script.

Enterprise recovery is optional and disabled by default. When enabled, three shares are created offline and any two are required. Shares must stay outside the server, Git, chat, tickets and normal backups.

See [DEPLOYMENT.md](DEPLOYMENT.md) for the operational procedure and [LLMWIKI.md](LLMWIKI.md) for implementation invariants.
