# Protocol Design Decisions

This document resolves the current protocol gaps for the first implementation. The out-of-band channel is user-managed and is intentionally outside this protocol’s implementation scope for now.

## 1. Bootstrap and discovery

The application does not scan public services automatically. A user supplies a candidate image or GIF to the decoder, or supplies a set of candidate files through an external workflow.

The receiver uses the negotiated discovery context to decide whether a carrier is a candidate. Discovery must be cheap and bounded, but failure must not reveal plaintext or detailed reasons to an untrusted caller.

Discovery context is distinct from:

- cryptographic salt
- identity key
- session key
- message authentication data

Each discovery context has an epoch, creation time, expiry, and status. Rotating the context invalidates future discovery attempts for the old epoch while allowing an explicitly configured transition period for in-flight messages.

The decoder must distinguish these outcomes internally:

```text
NotCandidate
CandidateButInvalid
CandidateAndUnauthenticated
ValidAuthenticatedMessage
ExpiredOrRevoked
```

The public API should avoid exposing unnecessary distinctions that would help an attacker test guesses.

## 2. Canonical processing pipeline

The first implementation should use this logical pipeline:

```text
plaintext
  -> optional bounded compression
  -> message framing and chunking
  -> authenticated encryption per chunk
  -> authenticated envelope assembly
  -> bounded error-correction encoding
  -> carrier adapter
```

On decode:

```text
carrier adapter
  -> bounded extraction
  -> error-correction recovery
  -> envelope parsing and size checks
  -> AEAD authentication and decryption
  -> chunk verification and reassembly
  -> optional decompression with strict limits
  -> plaintext
```

Error correction operates on the encrypted envelope, never on plaintext. A corrected payload is not trusted until all authentication checks pass. Uncorrectable, ambiguous, oversized, or unauthenticated data is rejected.

Each chunk should include or derive:

- session or identity context
- key epoch
- message ID
- chunk index and total count
- encryption-suite ID
- authenticated associated data

Chunk limits, correction strength, compression ratio, and total resource use must be bounded before allocation.

## 3. Asynchronous message state

The protocol must not assume a live connection or reliable delivery. A message is identified by `(sender identity, session epoch, message ID)` and a chunk by `(message ID, chunk index)`.

Receiver state should support:

- pending messages with an expiry
- duplicate chunk detection
- out-of-order chunk storage within a bounded window
- missing-chunk reporting when an acknowledgement path exists
- rejection of chunks from expired or revoked epochs
- garbage collection of incomplete messages

Acknowledgements are optional and transport-specific. The envelope protocol must work without them. Replaying an already accepted message must not produce a second application-level delivery.

Recommended initial state transitions:

```text
Unknown
  -> Candidate
  -> Authenticated
  -> PartiallyReceived
  -> Complete
  -> Delivered
  -> Expired / Revoked / Rejected
```

State transitions must be monotonic except for an explicit new epoch or new handshake. A failed authentication must not advance a valid session counter.

## 4. Key rotation and recovery

Every session has a key epoch. Rekeying creates fresh send and receive keys, a new epoch identifier, and fresh replay state derived from the authenticated session.

Rotation must define:

- message, byte, time, and carrier-count thresholds
- overlap rules for in-flight messages
- epoch expiration
- replay-window reset behavior
- failure and retry behavior
- explicit confirmation by both peers

The protocol cannot recover safely from a fully compromised current identity or session key using that same key alone. For the first version, identity replacement and revocation are user-managed through the out-of-band channel. The protocol must still carry the new identity fingerprint, epoch, effective time, and confirmation record so the transition is auditable and replay-protected.

## 5. Version and algorithm policy

Every envelope and control message contains an explicit protocol version and encryption-suite identifier. The implementation has a configured minimum accepted version and a set of supported versions.

Rules:

- unsupported versions fail closed with a stable error category
- versions cannot be downgraded through carrier data
- an upgrade is confirmed in the authenticated transcript
- old versions are rejected only after a documented transition date or user policy
- no field changes meaning between versions
- removed algorithms remain rejected even if a carrier requests them

The first release should ship one fully tested encryption suite. Algorithm agility must not become an untested collection of combinations.

## 6. Length, padding, and metadata leakage

Encryption does not hide message length, posting frequency, carrier selection, or timing. The envelope must define bounded size classes and optional padding policies.

Padding policy must specify:

- size classes
- maximum padding overhead
- whether padding is deterministic or random
- how padding interacts with error correction
- whether the carrier adapter can preserve it

Metadata policy must explicitly cover filenames, dimensions, color palettes, frame count, frame rate, timestamps, compression settings, and generated-carrier provenance. The tool must not claim that randomized metadata is automatically ordinary.

## 7. Carrier profiles

Each image/GIF adapter has a versioned carrier profile describing tested platform transformations.

A profile includes:

- source and output formats
- supported dimensions and frame counts
- payload and chunk capacities
- allowed transformations
- expected recovery rate
- metadata handling
- resource limits
- known failure modes

The user may choose a GIF strategy, such as selected-frame or distributed-frame placement, but every strategy must use the same authenticated envelope and obey the profile’s limits. Custom placement cannot bypass protocol checks.

Generated carriers and user-supplied carriers use separate policy paths. Generated carriers require their own evaluation and must not be treated as inherently indistinguishable.

## 8. Security evaluation

The project must maintain a representative corpus containing clean carriers and valid embedded carriers, with train/test separation and documented provenance.

Evaluation must include:

- blinded detection tests
- normal platform transformations
- compression, resizing, palette, and frame optimization tests
- false-positive and false-negative measurements
- confidence intervals
- payload-size and padding comparisons
- cross-version compatibility tests
- independent review of methodology

Evaluation results must state the detector model, corpus limits, transformations tested, and conditions under which claims do not apply. “Not detected in our test” is not equivalent to “undetectable.”

## 9. Secret and identity handling

The implementation must define protected storage for identity keys, session state, discovery contexts, and recovery records.

Minimum requirements:

- restrictive file permissions
- no secrets in filenames, logs, panic messages, or carrier metadata
- secure handling of temporary files
- best-effort memory zeroization
- encrypted backups or explicit prohibition of backups
- key and epoch rotation records
- clear lost-device and compromised-key procedures
- no automatic key export

The CLI must make identity fingerprints and current epochs inspectable without exposing private material.

## 10. Open implementation decisions

The following remain implementation choices, not protocol ambiguities:

- the exact envelope serialization format
- the initial PNG/GIF embedding algorithms
- the error-correction code and redundancy levels
- the initial size classes and padding limits
- the Noise handshake pattern
- the persistent state store
- the first supported platform transformation profiles

Each choice requires fixtures, benchmarks, failure tests, and a documented rationale before it becomes part of a released format.
