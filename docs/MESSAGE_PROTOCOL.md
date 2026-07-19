# Authenticated Message Protocol

This document defines the next protocol layer above the current authenticated public-key envelope. It deliberately excludes carrier encoding. The same message must be usable over an image, GIF, audio, video, text, or ordinary test transport. The current implementation now includes a text transport for protocol testing; it provides no covertness.

## 1. Goals and boundaries

The protocol must provide:

- recipient confidentiality;
- sender authentication against a user-verified identity key;
- authenticated context and algorithm selection;
- replay detection and duplicate suppression;
- asynchronous delivery with bounded pending state;
- explicit key epochs, rotation, and recovery;
- fail-closed parsing with bounded resource use.

The carrier is not trusted for identity, freshness, ordering, or capability negotiation. It transports an authenticated message but does not define its meaning.

## 2. Trust model

Each participant has:

1. a long-term Ed25519 identity key pair;
2. one or more X25519 recipient encryption keys or prekeys;
3. a locally stored trust record for the peer identity;
4. an epoch-specific replay and delivery record.

The user-managed secure channel provisions the peer identity fingerprint, recipient key or prekey bundle, protocol policy, context, and current epoch. A public key carried inside a message is only an assertion until it matches a trusted record or a valid authenticated key transition.

Fingerprint verification remains mandatory for first contact and identity changes. The handshake may deliver and rotate keys, but it must not promote an unverified identity merely because the key was received through VK or another carrier.

Private keys are never placed in a message or shared through the carrier.

## 3. Canonical message fields

The protocol uses a canonical, length-delimited encoding. Field order and integer endianness are fixed; implementations must not sign a language-specific serialization.

The target authenticated message contains:

```text
protocol_version       u8
suite_id               u8
message_type           u8
sender_identity_key    32 bytes
recipient_key_id       fixed-size key identifier
session_epoch          fixed-size epoch identifier
message_id             16 random bytes
created_at              u64 UTC seconds
expires_at              u64 UTC seconds
chunk_index             u32
chunk_count             u32
payload_length          u32
encrypted_payload       bounded bytes
sender_signature        64 bytes
```

The signature covers every field above except `sender_signature`, including the recipient key identifier, epoch, message ID, timestamps, chunk fields, and encrypted payload. The associated data for AEAD covers the same routing and protocol fields needed to prevent cross-context substitution.

The current MVP does not yet implement all of these fields. Its existing authenticated public envelope is the cryptographic foundation. The code now also provides a versioned X3DH-like bootstrap with signed recipient prekeys and fingerprint-gated sender verification; this produces a shared session key but is not yet a Double Ratchet.

## 4. Message identity and replay handling

`message_id` is generated with a cryptographically secure random generator. It is unique within the sender identity and session epoch. A receiver stores an accepted-message record keyed by:

```text
(sender_identity_fingerprint, session_epoch, message_id)
```

Before delivery, the receiver must:

1. verify the sender identity and signature;
2. verify the recipient key, context, suite, and epoch policy;
3. verify timestamp and expiry bounds;
4. reject an already completed message;
5. store acceptance atomically with application delivery state.

Replayed chunks must not cause a second application-level delivery. Duplicate and out-of-order chunks may be retained only within a bounded pending-message window.

Freshness is not inferred from the carrier upload time. Carrier timestamps and filenames are untrusted metadata.

## 5. Asynchronous delivery state

The receiver state machine is:

```text
Unknown
  -> Candidate
  -> Authenticated
  -> PartiallyReceived
  -> Complete
  -> Delivered
  -> Expired / Revoked / Rejected
```

State rules:

- `Candidate` contains bounded, unauthenticated data only.
- `Authenticated` is entered only after signature and policy checks succeed.
- `PartiallyReceived` accepts chunks in any order within configured limits.
- `Complete` requires every chunk and a verified message-level digest.
- `Delivered` is monotonic; a replay remains a duplicate.
- expired, revoked, or rejected records are retained long enough to prevent immediate replay, then garbage-collected.

Acknowledgements are optional and transport-specific. The message format must work without a response path.

## 6. Key epochs and rotation

Every peer relationship has a monotonically increasing `session_epoch`. A new epoch changes:

- the active recipient key or prekey;
- replay state;
- expiry policy;
- negotiated protocol parameters;
- any session-derived encryption keys.

An epoch transition must include an authenticated transition record containing:

```text
previous_epoch
new_epoch
new_key_id
effective_at
expires_previous_at
transition_nonce
```

The old identity key signs the transition when it is still trusted. If the old identity may be compromised, the transition must be confirmed through the user-managed secure channel and marked as a replacement rather than an ordinary rotation.

The user-facing confirmation value should be a stable, human-verifiable fingerprint derived from the authenticated identity record. QR and short-code displays are presentation formats for this fingerprint, not alternative trust models.

Only a deliberately configured overlap window may accept both epochs. After that window, old messages are rejected as expired, even if their cryptography remains valid.

## 7. Compromise and recovery

The protocol distinguishes:

- recipient encryption-key compromise;
- sender identity-key compromise;
- context or parameter compromise;
- device loss without key extraction.

A compromised identity cannot safely authorize its own replacement. Recovery therefore requires an out-of-band trust update, a new identity fingerprint, a new epoch, and invalidation of the old identity according to local policy.

The implementation must never silently replace a trusted identity because a carrier presents a new key.

## 8. Error and privacy behavior

External callers should receive a stable generic failure for malformed, unauthenticated, expired, unknown-identity, and wrong-recipient messages. Detailed reasons belong in local diagnostics and must not include plaintext or private key material.

Parsing must enforce maximum values before allocation:

- maximum envelope size;
- maximum chunk count;
- maximum chunk size;
- maximum pending messages per peer;
- maximum pending bytes per peer;
- maximum clock skew;
- maximum accepted lifetime.

## 9. Required implementation sequence

1. Add canonical message framing and a random message ID.
2. Add created/expiry timestamps and strict bounds.
3. Add chunk fields and message-level digest.
4. Add a small persistent replay/delivery store.
5. Add a Double Ratchet-style send/receive chain over the established session.
6. Add epoch records and authenticated rotation transitions.
7. Add recovery fixtures for identity replacement and revoked epochs.
8. Add golden wire fixtures and cross-version rejection tests.

No carrier adapter should implement its own replay, identity, or rotation logic.
