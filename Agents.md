# Engineering Procedures for the Steganography Project

This project is mission-critical software. Reliability, compatibility, security, and diagnosability take priority over delivery speed or feature count.

These procedures apply to human contributors, automated agents, scripts, and release tooling. No change is exempt because it appears small.

## Prime directive

Never trade a known invariant for an unmeasured convenience.

Every change must preserve the documented behavior of existing users, existing protocol data, and existing media where preservation is promised. If a requirement conflicts with compatibility or security, stop and document the conflict before implementing it.

## Threat model

The initial carriers are images and GIFs posted in chats, forums, and other public or semi-public services. The architecture must also support future audio and video carriers without changing the envelope or cryptographic protocol. The primary observer is an automated content-scanning system that may inspect public media, metadata, filenames, dimensions, timing, compression behavior, account-level patterns, and repeated carrier patterns. The system must not assume that a carrier remains unchanged after publication or retrieval.

The attacker is assumed to know the complete source code, algorithms, file formats, protocol specifications, and default configuration. Security must therefore depend on secret keys, correct randomness, authenticated state, and measurable carrier properties—not on obscurity or undisclosed implementation details. This is a mandatory application of Kerckhoffs's principle.

The project goals are confidentiality, sender authentication, replay resistance, tamper detection, and making the presence of a message difficult to establish from the carrier alone. Steganographic concealment is a measurable statistical property, not a guarantee of invisibility or plausible deniability. The project must not claim resistance to a determined human analyst, a trained detector with representative samples, platform-side re-encoding, or a compromised endpoint.

“Hard to prove” must be defined through an evaluation protocol: a blinded detector test, a representative carrier corpus, a declared false-positive/false-negative target, and tests after normal platform transformations. Results must be reported with confidence intervals and limitations. A successful decode is not evidence that the carrier is statistically indistinguishable from an untouched carrier.

The software, its verified implementation, and a value exchanged through an independent channel are trusted inputs. The secondary-channel value must be treated as a pre-shared secret or key-confirmation context, not as identity proof by itself. Sender identity must ultimately be bound to an authenticated identity key and the handshake transcript.

The design must account for:

- carrier replacement, truncation, recompression, resizing, frame changes, and metadata removal
- platform-specific transformations applied to public images and GIFs, including palette reduction, frame optimization, thumbnail generation, and format conversion
- modification of envelope fields and protocol messages
- replay, reordering, duplication, and delayed delivery
- an attacker who obtains an old carrier and an old ciphertext
- partial or total compromise of a session key
- malicious or malformed media files supplied to decoders
- endpoint compromise, stolen private keys, and leaked backups

The design must explicitly state what is not protected, including compromised endpoints, screenshots or plaintext copies, traffic-analysis metadata outside the carrier, and carriers that are destroyed by platform processing.

The design must also distinguish three separate claims:

1. **Confidentiality:** an observer cannot recover plaintext without the key.
2. **Integrity and authenticity:** an observer cannot modify or forge an accepted message without detection.
3. **Carrier indistinguishability:** an observer cannot reliably establish message presence from carrier evidence alone under the tested conditions.

Passing one claim does not imply passing the others.

## SQLite-inspired development discipline

The project should follow the qualities that make SQLite dependable:

- small, composable changes
- explicit invariants
- deterministic behavior
- extensive automated testing
- backwards-compatible file and protocol formats
- careful review of edge cases
- no unbounded resource consumption
- reproducible builds and releases

Prefer a boring implementation that is easy to audit over a clever implementation that is difficult to reason about. Minimize dependencies, isolate platform-specific code, and avoid adding a new abstraction until the existing boundary is demonstrably insufficient.

## Repository structure and ownership

- `codebase/` contains the Rust application source.
- `docs/` contains architecture, protocol, security, and operational documentation.
- `Dockerfile` and `docker-compose.yml` define the supported development environment.
- Generated output such as `target/` must never be committed.
- Each crate must have a clear owner, public API boundary, and documented invariants.

Changes that cross crate boundaries require review of all affected callers and tests. Do not silently modify a public type, serialized representation, protocol message, error meaning, or command-line behavior.

## Required change procedure

Before editing:

1. Read the relevant architecture and protocol documentation.
2. Inspect current tests, call sites, and serialized fixtures.
3. State the invariant or user-visible behavior the change must preserve.
4. Identify compatibility, security, migration, and rollback risks.
5. Define tests that will fail if the change is incorrect.

During editing:

- Make one logical change at a time.
- Keep commits focused and reviewable.
- Do not mix formatting-only changes with behavior changes.
- Do not rewrite a subsystem without a written design decision.
- Do not remove a test because it is inconvenient; fix or replace it with an equivalent stronger test.
- Do not use generated code or unsafe code without documenting why it is necessary and how it is verified.

After editing:

1. Format the code.
2. Run unit, integration, property, and relevant fuzz tests.
3. Run dependency and security checks.
4. Test compatibility with existing fixtures and previously released formats.
5. Review the diff for accidental API, protocol, logging, and error changes.
6. Record any remaining risk and the rollback procedure.

## Compatibility policy

Compatibility is a feature. Existing valid data must remain readable unless a documented, tested deprecation policy says otherwise.

Serialized envelopes, key files, protocol messages, and CLI output that users may script against must have:

- explicit version numbers
- canonical encoding rules
- defined unknown-field behavior
- strict size and nesting limits
- documented upgrade and downgrade behavior
- fixture tests retained across releases

New readers should tolerate fields they do not need when safe. New writers must not emit a format that older readers cannot safely reject or process. Never reinterpret an existing field or identifier.

Breaking changes require a new major format or protocol version, a migration plan, a compatibility window, release notes, and explicit approval from the project maintainers.

If the product intentionally refuses old versions, define and test a minimum accepted version plus an upgrade deadline. “No old version support” must not mean silently failing to decode existing user data or creating an unauthenticated downgrade path.

## Database and state changes

If persistent state is added later, use SQLite-inspired migration procedures:

- migrations are numbered, immutable, and applied in order
- each migration is transactional where possible
- migrations are idempotent or detect partial application safely
- schema versions are recorded in the database
- old databases are backed up before migration
- migration tests cover empty, current, and representative historical databases
- downgrade behavior is documented; destructive downgrades are never implicit
- migration failures leave the previous valid state recoverable

Never edit an already-released migration. Add a new migration. Never use a destructive schema operation without an export, backup, recovery test, and explicit operator confirmation.

## Cryptography and protocol rules

Cryptographic primitives must come from reviewed, maintained libraries. Do not implement encryption, hashing, signature, key exchange, nonce generation, or random-number generation manually.

- Every encrypted message must use authenticated encryption.
- Nonces must never repeat for a key.
- Key purpose and direction must be separated through domain-separated derivation.
- Identity keys and ephemeral session keys must remain distinct.
- Private keys must never appear in logs, test output, carrier metadata, or error messages.
- Algorithm identifiers, protocol versions, counters, and message types must be authenticated.
- Discovery context, cryptographic salt, and authentication material must have separate semantics and domain separation; a salt must not be treated as identity proof or an implicit locator.
- Replay protection must be explicit and tested.
- Unsupported algorithms and protocol versions must fail closed.
- Rekeying must have a defined boundary and recovery behavior.
- Changes to the handshake require a protocol design review and interoperability fixtures.

Do not describe an unauthenticated control channel as trusted. Any control message embedded in a carrier must be authenticated, authorized, versioned, replay-protected, and auditable.

### Key lifecycle and compromise response

Key management is part of the protocol, not an afterthought.

- Long-term identity keys must be separate from session and carrier keys.
- The secondary-channel secret must be mixed into a documented, domain-separated derivation or authenticated handshake; it must never be used directly as an encryption key.
- If the secondary-channel value is human-readable or low entropy, use a password-authenticated key exchange or an approved memory-hard derivation such as Argon2id with a unique public salt; do not rely on a fast hash.
- Every session and key epoch must have an unambiguous identifier.
- Session keys must provide forward secrecy where practical.
- Rekeying must be supported before a configured message, byte, time, or carrier-count limit is reached.
- A rekey must authenticate the prior session, establish fresh key material, confirm both directions, and define how in-flight messages are handled.
- Key rotation must not silently reset replay counters or accept messages from an obsolete epoch.
- Compromise recovery must support revoking an identity, creating a replacement identity, and rejecting old keys after an explicit transition.
- Private keys and secondary-channel secrets must have restricted permissions, protected backups, rotation records, and secure deletion procedures where the platform supports them.
- Key compromise tests must verify that old session keys cannot decrypt future epochs and that a stolen old key cannot impersonate a newly rotated identity.

The protocol must document whether a secondary-channel secret is a password, a pre-shared key, a confirmation code, or merely a non-secret context value. Calling a value a “salt” does not make it secret or authenticate a person.

Peers may exchange protocol parameters through an independent secure channel. Such out-of-band parameters must be canonicalized, authenticated to the intended identities, bound to the handshake transcript, scoped to an epoch, and given an expiry. Public-carrier parameters must never silently override the out-of-band agreement. Parameter negotiation must reject downgrade, replay, truncation, ambiguity, and unsupported values.

## Steganography and media rules

Media adapters are responsible for declaring their actual guarantees. They must not claim that embedded data survives transformations they have not tested.

Every adapter must define:

- supported formats and codecs
- maximum practical payload size
- behavior under truncation and corruption
- behavior after metadata changes
- behavior after lossless and lossy re-encoding
- whether processing is deterministic
- memory, CPU, duration, and file-size limits

Never overwrite a source carrier by default. Preserve the original and write a new output path. Refuse ambiguous or unsafe format detection.

### Extensible carrier architecture

Images and GIFs are the first milestone, not a permanent architectural limitation. The medium-independent layer must support future audio and video adapters through capabilities rather than format-specific assumptions.

The carrier abstraction should be able to describe:

- still, frame-based, and continuous media
- complete-file and streaming processing
- capacity, chunk size, ordering, and reassembly requirements
- lossless, lossy, and platform-transformed behavior
- metadata, timing, frame-rate, sample-rate, and codec constraints
- bounded memory, CPU, disk, and processing duration
- whether an adapter can verify a carrier before decoding it

The envelope, encryption, authentication, replay protection, and control protocol must remain media-independent. Audio and video adapters must not duplicate cryptographic or message-framing logic. Large media must use authenticated chunking and resumable or fail-closed processing where appropriate.

Do not design the image adapter around assumptions that would block streaming audio/video later, such as requiring every carrier to fit in memory, assuming a two-dimensional pixel grid, or encoding protocol state in format-specific metadata.

Concealment claims must be measured against the declared observer model. Tests should record the effect of normal publication transformations and should distinguish confidentiality from statistical detectability. Do not promise that a message is invisible merely because a decoder can recover it.

### Hostile media handling

Media files are untrusted binary input. A malicious carrier can exploit a decoder or cause denial of service even when no valid hidden message exists. Examples include:

- decompression bombs with small files that expand to enormous images, audio buffers, or frame sets
- integer overflows in dimensions, durations, sample counts, offsets, or chunk lengths
- malformed nested containers, recursive metadata, and conflicting format headers
- truncated or adversarially ordered chunks that trigger excessive allocation or CPU use
- codec vulnerabilities reached through native libraries or FFI
- polyglot files that are interpreted differently by different tools
- parser differentials where validation and decoding disagree
- embedded scripts, active metadata, or unexpected external-resource references

Every decoder must validate magic bytes, lengths, dimensions, frame counts, durations, nesting depth, and allocation estimates before expensive processing. Decoding should run with bounded memory and CPU, preferably in an isolated process or sandbox when native codec libraries are involved. Never execute embedded content. Fuzz each parser and treat decoder crashes as security defects.

## Testing requirements

Tests are part of the product, not an optional verification step.

Required test categories include:

- unit tests for every public behavior
- integration tests across crate boundaries
- round-trip tests for every carrier adapter
- historical fixture tests for every supported envelope version
- malformed, truncated, corrupted, and oversized input tests
- incorrect-key and authentication-failure tests
- replay and counter-ordering tests
- property-based tests for parsers and serializers
- fuzz tests for all untrusted binary input
- deterministic test vectors for cryptographic protocol steps
- resource-limit and denial-of-service tests
- cross-platform tests for supported environments

Any bug found in production must receive a regression test before the fix is considered complete.

### Detectability benchmark

The project must maintain an independent detector benchmark for every supported carrier profile. It must compare clean and encoded carriers using reproducible corpus manifests, disjoint data splits, negative controls, and declared operating points. Results must include false-positive and false-negative rates, confidence intervals, and breakdowns by carrier type, payload size, and transformation pipeline.

The benchmark is an evaluation instrument, not a guarantee that an attacker uses the same detector. Improving a benchmark score by breaking decoding, authentication, interoperability, or carrier usability is a regression. Dataset leakage, reuse of related carriers across splits, and undocumented preprocessing invalidate a result.

## Error handling and observability

Errors must be typed, actionable, and safe to expose. Do not leak plaintext, private key material, carrier contents, or sensitive peer identity data.

Each failure should identify the subsystem and stable error category while avoiding implementation details that callers cannot rely on. Logs must be structured, redact secrets by default, and include correlation IDs where useful.

Never ignore an error, panic on untrusted input, or convert a meaningful error into a generic success response. Panics are reserved for impossible internal invariants and must be covered by tests.

## Dependency and build policy

- Pin or constrain dependency versions deliberately.
- Review every new dependency for maintenance, license, security, and transitive dependency impact.
- Keep `Cargo.lock` under version control for the application.
- Use reproducible Docker builds and document the base-image update process.
- Run offline or locked builds in CI where practical.
- Do not rely on network access at runtime for cryptographic correctness.
- Keep unsafe Rust to an audited minimum.

## Review gates

No change is ready to merge until all applicable gates pass:

- `cargo fmt --check`
- `cargo check --workspace --all-targets --locked`
- `cargo test --workspace --all-targets --locked`
- clippy with warnings treated as errors for project code
- dependency and license checks
- security and secret scanning
- protocol and fixture compatibility tests
- fuzzing or parser stress tests for changed binary formats
- documentation updated for user-visible behavior

Changes to cryptography, protocol formats, key handling, media parsing, persistence, or security boundaries require focused human review in addition to automated checks.

## Release procedure

Every release must have:

1. a reviewed changelog
2. a recorded version and format/protocol compatibility statement
3. reproducible build inputs
4. passing tests on supported platforms
5. migration and rollback instructions where applicable
6. a security review of relevant changes
7. release artifacts verified by checksums or signatures
8. a staged or canary deployment when operationally applicable
9. a post-release monitoring and rollback owner

Do not release with known data-loss, key-compromise, silent-corruption, or compatibility defects. A missing feature is preferable to an unsafe release.

## Incident response

For suspected key compromise, data corruption, protocol breakage, or unsafe media parsing:

1. stop affected releases or processing paths
2. preserve logs, fixtures, and reproduction inputs without exposing secrets
3. identify affected versions and data formats
4. publish a safe mitigation or disablement path
5. add a regression test
6. issue a migration, rotation, or revocation plan
7. document the root cause and preventive control

Never delete evidence or silently change behavior to hide an incident.

## Agent behavior

Automated agents must:

- inspect before editing
- make minimal, reversible changes
- never fabricate test results
- report commands that could not run and why
- preserve unrelated user changes
- avoid destructive commands unless explicitly authorized
- ask for direction when a breaking change or security tradeoff is unavoidable
- summarize changed files, verification performed, and remaining risks

An agent must not mark a task complete merely because code compiles. Completion requires the applicable compatibility, testing, documentation, and security checks.

## Definition of done

A feature is complete only when:

- the design and invariants are documented
- the implementation has focused tests
- old valid data remains supported or migration is documented
- malformed and adversarial inputs are handled safely
- operational limits are enforced
- errors and logs are reviewed for information leakage
- CI checks pass
- the change is reviewable and reversible
- release and rollback impact is understood
