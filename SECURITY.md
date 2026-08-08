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
- plaintext vault names, titles, accounts, URLs, notes, folders, tags or credentials;
- plaintext search indexes;
- plaintext enterprise recovery shares or a reconstructed recovery private key.

The Web E2EE model still trusts the JavaScript currently served to the browser. It does not protect against a malicious build, XSS, a compromised endpoint, a malicious browser extension, keylogging, screen capture, browser vulnerabilities or an authorized user exporting data. Weak master passwords may be guessed offline. Revocation cannot erase content a former member already viewed or copied.

Platform administrators are inside the service trust boundary for operations but do not receive vault keys through that role. Including platform administrators, nobody can use the platform to inspect a protected vault. Enterprise recovery can only return an approved set of still-valid permissions to the original user; it does not expose a browsing path or let an administrator sign in as that user.

When enterprise recovery is enabled, two to six administrators each receive one Shamir share sealed to that administrator's account public key. The service stores only ciphertext. The first approving administrator opens one share inside the Crypto Worker and relays it encrypted to the other administrators. The second approving administrator combines that relay with their own share inside the Crypto Worker, reconstructs the recovery key only long enough to create vault envelopes for the user's new account public key, and then destroys the temporary key material. The service still verifies both administrators, current device signatures, account key generations, live authorization, vault epochs and recovery evidence without receiving a master password, plaintext share, recovery private key or vault key.

## Non-negotiable invariants

- Authentication providers identify a user; they never unlock user data.
- Group membership never grants `platform-admin`; the role requires an explicit local assignment.
- A platform administrator does not automatically receive vault keys.
- User groups express authorization sets and never own a shared group key.
- Saving a user or group authorization is the complete product action. Only an unlocked owner client may generate the recipient's individual envelope in the background; the server never generates or holds a vault key, and ownership transfer still requires explicit acceptance.
- If no owner client is unlocked, envelope delivery waits safely and resumes on the next owner unlock, reconnect or relevant crypto event without asking an administrator to approve the authorization again.
- Locking destroys decrypted projections, search indexes and active key material; failures remain locked.
- The API validates authorization, versions, signatures and ciphertext structure but does not implement client decryption.
- Existing database migrations are immutable and protected by `apps/api/src/db/migration-lock.json`.
- Demo authentication requires `MIMA_DEMO_MODE=true` and loopback-only origins.
- Production extension builds require HTTPS and a deployment-specific stable manifest identity.
- An administrator account being ready, signed in or unlocked is not a recovery-setup approval. Setup and rotation require explicit confirmation from two different administrators; passive login must never count toward the two-person control.

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

Enterprise recovery is optional and disabled by default. When enabled, configure two to six explicit platform administrators; any recovery requires exactly two different administrators. Encrypted custody shares are part of the database state and are useless without the corresponding administrator account private keys. Plaintext shares, relays after decryption, reconstructed recovery keys and vault keys must never enter the service, Git, chat, tickets, logs or normal browser storage.

For a forgotten master password, an administrator starts one recovery case, the user chooses a new master password, and two different administrators confirm the user's identity. The second administrator's browser automatically creates the approved target envelopes. Revoked permissions, stale administrator or target key generations, changed administrator sets, changed vault epochs and expired cases are rejected before delivery. A personal vault may be replaced only when the transaction proves that it has no active records, history, folders or blocking references; the replacement vault is initialized with active recovery coverage.

The repository retains the previous offline-share protocol and tool for compatibility and auditability, but it is not part of the normal UI and cannot process the current account-custody key. Returning to offline custody requires a new recovery key, complete owner-driven vault coverage and retirement of the previous key.

See [DEPLOYMENT.md](DEPLOYMENT.md) for the operational procedure and [LLMWIKI.md](LLMWIKI.md) for implementation invariants.
