# Steganography Tool Project Plan

## Goal

Build a Rust tool that can embed encrypted data into multiple types of media while keeping the cryptographic protocol, payload format, and carrier-specific implementation separate.

The first release should support images/GIFs well, then expand through independent adapters for audio and video without changing the envelope, cryptographic protocol, or session model.

## Design principles

- Do not implement cryptographic primitives ourselves.
- Keep encryption independent from steganographic encoding.
- Use versioned, authenticated protocol messages.
- Treat every media format according to its capacity and re-encoding behavior.
- Fail closed when data is corrupted, replayed, unsupported, or unauthenticated.
- Preserve the original carrier by default.
- Make protocol changes explicit, negotiated, and auditable.

## Proposed workspace

```text
stegano/
├── crates/
│   ├── core/          # Shared types, configuration, and errors
│   ├── envelope/      # Framed payload format
│   ├── crypto/        # Encryption, signatures, and key agreement
│   ├── protocol/      # Handshake and authenticated control messages
│   ├── stego/         # Medium-independent carrier interface
│   ├── image/         # PNG, JPEG, WebP, and BMP adapters
│   ├── animation/     # GIF and animated image adapters
│   ├── audio/         # WAV, FLAC, Ogg, and later other formats
│   ├── video/         # Video container and codec integrations
│   ├── detector/      # Research benchmark for carrier detectability
│   └── cli/            # Command-line application
└── tests/
```

The current `codebase/` directory is the initial application workspace. The Cargo workspace can be split into crates once the first prototype has stabilized.

## Envelope format

All media adapters should encode the same binary envelope. The carrier should not need to understand the plaintext or cryptographic details.

The envelope should contain:

- magic bytes
- protocol version
- message ID
- payload type
- encryption-suite ID
- compression settings
- sequence number
- payload length
- encrypted payload
- authentication tag
- optional padding
- optional authenticated control message

Metadata that affects verification or decryption must be authenticated as associated data. This prevents an attacker from changing the selected algorithm, message type, sequence number, or length without detection.

Large payloads should be split into authenticated chunks. The format needs explicit limits for total size, chunk count, and decompressed size.

Envelope discovery may use a secret or rotating context value, but discovery data must be modeled separately from cryptographic salts. A salt is normally non-secret and must not be treated as proof of identity. Discovery, key derivation, and authentication inputs require separate fields, purposes, rotation rules, and tests.

Peers may provision or negotiate salts, discovery context, protocol versions, carrier policies, and supported algorithm suites through an independent secure channel. This out-of-band parameter bundle must have a canonical encoding, an expiry, an epoch or transaction identifier, and an authenticated transcript hash. Parameters received through the public carrier must be checked against that authenticated bundle and must not silently override it.

The first version may process complete files rather than stream audio or video. Its interfaces should still avoid requiring cryptographic state to depend on an entire carrier, so streaming can be added later without changing the envelope or session protocol.

Payloads may use bounded error correction inspired by QR systems. Error correction must be applied before authenticated verification, with strict limits on correction work and a fail-closed result when the recovered envelope is not authentic. Redundancy, capacity, and detectability tradeoffs must be measured for each carrier.

## Cryptography

Use established libraries and protocols rather than writing cryptographic primitives.

Initial algorithm suite:

- X25519 for key agreement
- Ed25519 for identity signatures
- HKDF-SHA256 for key derivation
- ChaCha20-Poly1305 as the initial AEAD
- AES-256-GCM as an optional additional suite

The application should expose an algorithm registry with stable identifiers. Each suite must define its key sizes, nonce rules, authentication behavior, and compatibility requirements.

The implementation should support one suite completely before adding alternatives. The MVP now exposes symmetric mode and a hybrid X25519/ChaCha20-Poly1305 recipient-encryption mode. Algorithm changes must be negotiated and authenticated, never silently selected from unauthenticated input.

In public-key mode, the sender generates an ephemeral X25519 key pair, derives a one-time AEAD key with the recipient public key, and stores the ephemeral public key in the envelope. The sender also signs the authenticated envelope fields with a long-term Ed25519 identity key and stores the identity public key alongside the ephemeral key. The recipient must compare that embedded key with a trusted key provisioned out of band before accepting the message. This provides recipient confidentiality, forward secrecy for that message, and sender authentication; identity rotation and revocation remain explicit protocol work.

## Handshake and sessions

Use an established handshake pattern, preferably a Noise Protocol Framework pattern or a well-reviewed equivalent, rather than inventing a new key exchange.

Each identity should have:

- a long-term signing key pair
- a public identity fingerprint
- separately generated ephemeral session keys

The handshake should provide:

1. identity or pre-shared-key authentication
2. ephemeral key exchange
3. transcript authentication
4. session key derivation
5. algorithm negotiation
6. replay protection
7. explicit session confirmation
8. rekey support

A session can be represented by:

```text
session_id
peer_identity
encryption_suite
send_key
receive_key
send_counter
receive_counter
```

Private keys must never be embedded in a carrier or written to logs. Key export should require an explicit command and use a protected format.

## Authenticated control protocol

Protocol control messages may be carried inside the encrypted envelope. They should be versioned and authenticated rather than relying on an undocumented backchannel.

Initial control message types:

- `NewHandshake`
- `ConfirmHandshake`
- `RequestRekey`
- `ChangeCipherSuite`
- `CapabilityRequest`
- `CapabilityResponse`
- `CloseSession`

Control messages must require an established trust relationship or valid handshake context. Counters, nonces, and challenge-response values should prevent replay. Unknown commands must be rejected safely.

Requests for a new key or handshake procedure must specify the current session or identity context, an expiry, and the required authorization. A peer must not accept an unauthenticated request to weaken security or change protocol behavior.

The protocol is asynchronous. It must handle delayed, duplicated, reordered, missing, and permanently deleted carriers. It needs explicit message IDs, chunk IDs, replay windows, expiry behavior, and a defined acknowledgement strategy. It must not assume a live bidirectional connection.

Key rotation and new-handshake requests are protocol operations, but recovery from a compromised current key cannot depend solely on that key. Revocation, identity replacement, and recovery from a lost or compromised endpoint require an independent trust path or pre-established recovery authority.

Changing encryption should follow this sequence:

1. authenticate a capability or algorithm request
2. verify that both peers support the requested suite
3. perform a fresh key derivation or handshake
4. confirm the new session
5. switch counters and keys at a defined protocol boundary
6. retain a bounded transition window for in-flight messages

## Carrier abstraction

Media-specific code should implement a common interface similar to:

```rust
trait Carrier {
    type Error;

    fn inspect(&self) -> Result<CarrierInfo, Self::Error>;
    fn capacity(&self) -> Result<Capacity, Self::Error>;
    fn encode(&self, envelope: &[u8]) -> Result<Vec<u8>, Self::Error>;
    fn decode(&self) -> Result<Vec<u8>, Self::Error>;
}
```

`CarrierInfo` should describe:

- media format
- dimensions or duration
- estimated capacity
- lossless or lossy behavior
- whether metadata is preserved
- whether re-encoding can destroy embedded data

The interface should eventually support streaming for large audio and video carriers, while the first implementation may operate on complete image/GIF files. The initial interfaces should still expose capabilities and resource limits so later streaming adapters do not require a protocol rewrite.

GIF behavior should be selectable through an explicit policy. A policy may choose frame distribution, selected-frame embedding, custom placement, or other supported strategies. Every policy must define ordering, capacity, transformation tolerance, and validation behavior. Custom strategies must not bypass authentication, resource limits, or carrier safety checks.

The tool should support both user-supplied carriers and generated carriers. These are separate modes with separate validation and policy checks. Generated carriers must not be treated as automatically safe or indistinguishable; they require the same evaluation and metadata policy as supplied carriers.

Metadata handling should be explicit. The tool must identify which metadata is preserved, removed, normalized, or intentionally varied, and must test whether those choices create detectable patterns. “Looks like ordinary noise” is an evaluation target, not a security guarantee.

## Media roadmap

### Images

Start with PNG because it is lossless and easy to test. Later add BMP, JPEG, and WebP. Lossy formats must report fragility and should not promise that embedded data survives arbitrary re-encoding.

### GIF and animation

Support animated frames as a separate adapter. Define whether data is distributed across frames or stored in selected frames, and test behavior after frame optimization.

### Audio

Start with WAV and FLAC. Add Ogg and other lossy formats only with clear capacity and durability warnings.

### Video

Begin with a narrow, documented container/codec combination. Treat video as a stream of frames with optional audio rather than attempting to support every codec at once.

## CLI outline

Initial commands:

```text
stegano keygen
stegano key inspect
stegano encode --input message.txt --carrier image.png --output encoded.png
stegano decode --input encoded.png --output message.txt
stegano inspect --input image.png
stegano handshake initiate ...
stegano handshake accept ...
```

The CLI should refuse to overwrite the input carrier unless explicitly requested. `inspect` should report capacity, format, estimated overhead, and compatibility warnings without exposing plaintext.

## Milestones

### Milestone 1: secure core

- Cargo workspace foundations
- envelope serialization and parsing
- ChaCha20-Poly1305 encryption
- key generation and protected key files
- PNG adapter
- `keygen`, `encode`, `decode`, and `inspect` commands

### Milestone 2: authenticated sessions

- X25519 and Ed25519 identities
- handshake transcript
- session encryption
- replay protection
- rekey control message
- protocol version negotiation

Protocol version policy must define a minimum accepted version, an upgrade path, and a clear rejection error. If old versions are intentionally unsupported, the transition must be announced and tested before enforcement; otherwise rejecting old data can become an avoidable availability failure.

### Milestone 3: more image formats

- BMP
- JPEG
- WebP
- GIF frame support

### Milestone 4: audio

- WAV
- FLAC
- capability reporting for lossy formats

### Milestone 5: video

- one documented container and codec path
- frame-level embedding
- streaming payload support
- corruption and re-encoding tests

## Testing and security requirements

Every adapter should have tests for:

- encode/decode round trips
- empty and maximum-size payloads
- corrupted payloads
- truncated carriers
- incorrect keys
- replayed messages
- altered metadata
- unsupported protocol versions
- carrier re-encoding

The cryptographic layer should include known-answer tests where available, key separation tests, nonce-uniqueness checks, and fuzz tests for envelope parsing.

Before production use, the protocol and key-management design should receive an independent security review. Steganographic capacity and detectability are media-specific properties and should be measured rather than assumed.

## Detector and benchmark tool

The project will maintain a separate detector tool alongside the encoder. Its purpose is to benchmark carrier detectability and expose regressions during development; it is not part of the production protocol and must not be treated as a universal detector.

The first benchmark should compare clean and encoded PNG/GIF carriers using reproducible baseline measurements, including per-channel LSB statistics, local noise and residual measurements, payload size, image metadata, repeated-carrier comparisons, transformation effects, and a held-out classifier baseline.

The next protocol milestone is defined in [docs/MESSAGE_PROTOCOL.md](MESSAGE_PROTOCOL.md). It establishes canonical message framing, authenticated message identity, replay suppression, asynchronous chunk state, key epochs, rotation, and compromise recovery before those concerns are added to carrier adapters.

## Protocol-first implementation order

The secure communication layer is the project baseline. Carrier embedding is intentionally downstream of it.

1. Implement the custom-key, Signal-inspired identity and prekey handshake with mandatory fingerprint verification.
2. Establish authenticated session state, message keys, replay handling, rotation, and recovery over the text transport.
3. Treat encrypted text as the reference transport for protocol tests and interoperability fixtures.
4. Add PNG and GIF carrier adapters without changing the message or session protocol.
5. Add audio and video adapters only after their transformation profiles and recovery behavior are independently tested.

This order allows carrier experiments to change without changing the cryptographic trust model.

The benchmark must use disjoint training, validation, and test sets. Carriers derived from the same original source must not cross dataset splits. Every run records the tool version, corpus manifest hash, carrier profile, payload size, transformation pipeline, random seed, and model configuration.

Required metrics include false-positive and false-negative rates at declared operating points, precision, recall, ROC/PR curves, confidence intervals, and performance by carrier type, payload size, and transformation. Negative controls must include naturally noisy carriers and ordinary image processing so the detector does not merely recognize unrelated artifacts.

The detector becomes a development gate only after its corpus, metrics, and baseline are independently reviewed. Improving a score by breaking decoding, authentication, interoperability, or carrier usability is a regression.

The first implementation may expose a `blind-detect` command that reports a reproducible score from a single candidate carrier. Its threshold must be treated as experimental until calibrated against a representative clean corpus. A score from one carrier or one threshold is not a security claim.

## Immediate next steps

1. Convert the current sample into a Cargo workspace.
2. Define the envelope types and serialization format.
3. Add a crypto crate using one reviewed AEAD suite.
4. Implement a PNG adapter behind the carrier trait.
5. Add round-trip, corruption, and size-limit tests.
6. Add key generation only after the encrypted envelope is stable.
7. Design the handshake against a selected Noise pattern.
8. Create the detector corpus and baseline before making further embedding changes.
9. Add detector evaluation to carrier-profile and release review.
