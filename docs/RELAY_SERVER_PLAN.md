# SafeChat Relay Server Plan

## 1. Goal

Build a standalone Rust server that appears to clients as a normal HTTPS web
API. It acts as one optional SafeChat transport alongside copy/paste and
image/audio/video carriers.

The relay is not part of the Signal cryptographic session. Clients continue to
own identity keys, fingerprint verification, sessions, ratchets, message
decryption, message IDs, history, recovery, and revocation decisions.

The server routes and stores opaque client payloads. It must never need access
to client private keys or message plaintext.

## 1.1 Initial implementation decisions

- Allowlist administration is performed through a server CLI.
- Each client generates its own random client ID and one-time enrollment secret.
- The administrator enters the client ID, fingerprint, and enrollment secret
  through the CLI.
- SQLite is the initial relay database.
- The standalone relay terminates native TLS directly.
- Every authenticated API request carries a client identity-key signature,
  alongside session credentials where applicable.
- Each allowlist entry represents one device; account and multi-device grouping
  are deferred.
- Clients use an active WebSocket with cursor-based HTTP polling as a
  reconnect/background fallback.
- WebSocket frames use versioned JSON with URL-safe Base64 payload fields.
- The WebSocket upgrade uses the access credential; client frames carry signed
  nonces, timestamps, and request hashes.
- Clients send their last cursor on connect; the server reconciles missed queue
  items before streaming new events.
- Acknowledgements are supported both as WebSocket frames and HTTP requests.
- Only one active WebSocket is allowed per client ID; a newer connection
  replaces the older one.
- The server sends keepalive pings every 30 seconds and clients reconnect with
  exponential backoff, falling back to HTTP polling when necessary.
- The queue supports explicit acknowledgements and message expiry.

The relay is a separate server product. It must be independently buildable and
deployable without the SafeChat client UI, client profile layout, client SQLite
database, or client runtime state. It may implement the versioned SafeChat HTTP
contract and verify public signatures, but it must not import client
application modules or depend on client filesystem paths.

## 2. Architecture

```text
SafeChat messenger core
├── Signal identities, sessions, and encryption
├── Peer/lobby state
├── Message IDs and history deduplication
├── Recovery and revocation verification
└── Transport interface
     ├── Copy/paste text adapter
     ├── Image carrier adapter
     ├── Audio/video carrier adapter
     └── HTTPS relay adapter
              │
              ▼
       Standalone HTTPS relay server
       ├── Device authentication
       ├── Bundle directory
       ├── Opaque message queues
       ├── Recovery-record distribution
       └── Rate limits and quotas
```

The relay is an adapter, not the new messenger core. The UI should continue to
use `/s`, `/r`, `/send`, and `/receive` regardless of the selected transport.

For the first relay deployment, both clients must be explicitly approved by
the relay administrator before they can use that server as a transport:

```text
Client A ── client ID + public fingerprint ──┐
                                             ├─> Relay administrator
Client B ── client ID + public fingerprint ──┘
                                             │
                                             ▼
                                      Server allowlist
                                             │
Client A/B ── HTTPS identity authentication ─┘
```

The administrator adds each client ID while binding it to the corresponding
public identity key and fingerprint. The administrator does not receive a
private key. Once approved, both clients can use the server for bundle
publication, bundle lookup, ciphertext submission, and queued-message polling.
Peer-to-peer fingerprint verification remains a separate client responsibility;
being allowed onto the same relay does not make two clients trusted peers.

## 3. Transport-neutral client contract

Before implementing the server, define a client-side transport interface with
operations equivalent to:

```text
publish_bundle(peer/device identity, public bundle)
fetch_bundle(peer/device identity)

send_message(recipient, opaque encrypted payload)
receive_messages(cursor)
acknowledge_message(server message reference)

publish_recovery_record(signed record)
fetch_recovery_records(cursor)
```

Each transport can support only the operations it can provide:

| Transport | Publish | Receive | Offline queue | Acknowledgements |
|---|---:|---:|---:|---:|
| Copy/paste | Display | Paste | Manual | No |
| Image/audio/video | Encode | Extract | Carrier-dependent | No |
| HTTPS relay | HTTP request | HTTP request | Yes | Server-level only |

The messenger must not assume that a transport is live, bidirectional, ordered,
or reliable.

## 4. HTTPS API

Use versioned HTTPS endpoints with ordinary JSON request/response bodies. Binary
payloads should be URL-safe Base64 strings. The server should expose no custom
cryptographic protocol over the wire beyond signed SafeChat control records.

### Health and capabilities

```http
GET /v1/health
GET /v1/capabilities
```

These endpoints expose service health and protocol/API versions, not user data.

### Device registration

```http
POST /v1/devices/register
```

The client submits:

- SafeChat device address;
- public identity key and fingerprint;
- current public prekey bundle;
- server challenge signature proving possession of the identity private key.

The server returns an opaque device identifier and an API credential. Private
keys never leave the client.

### Bundle directory

```http
PUT /v1/devices/{device}/bundle
GET /v1/devices/{device}/bundle
```

The server stores and returns public prekey bundles. It should verify that a
bundle update is authorized by the registered device identity, but peer
fingerprint verification remains a client responsibility.

### Message submission and retrieval

```http
POST /v1/messages
GET  /v1/messages?cursor={cursor}
POST /v1/messages/{server_id}/ack
GET  /v1/messages/status?message_id={message_id}
GET  /v1/events                         # HTTPS WebSocket upgrade
```

A submitted message contains:

- recipient device identifier;
- SafeChat message ID;
- opaque Signal envelope;
- optional client expiry;
- optional client timestamp.

The server adds its own queue identifier and acceptance timestamp. The server
may acknowledge queue acceptance and retrieval, but cannot determine whether a
recipient successfully decrypted or displayed a message.

Message delivery uses a hybrid HTTP model. Clients maintain an authenticated
WebSocket while the UI is active and receive new queue items over that
connection. Cursor-based HTTP polling remains the reconnect and background
fallback. This avoids platform push-notification dependencies while allowing
responsive delivery on desktop and foreground mobile clients. Correctness must
not depend on a WebSocket remaining open.

### Recovery records

```http
POST /v1/recovery
GET  /v1/recovery?since={cursor}
```

Recovery records remain signed by the old identity and are verified by clients.
The server distributes them but does not decide whether a peer should accept a
new fingerprint.

## 5. Authentication and authorization

### Initial registration

1. Client requests registration.
2. Server returns a challenge.
3. Client signs the challenge with its Signal identity private key.
4. Server stores the public identity and issues an API credential.

### Routine requests

Routine requests use the issued credential over TLS. Sensitive control-plane
operations should also include a request signature or equivalent proof tied to
the registered device identity.

### Identity replacement

When a client replaces its identity:

1. The old identity signs the SafeChat recovery record.
2. The client publishes the record through the server.
3. The server associates the replacement with the existing device account only
   after validating the signed recovery authorization.
4. Peers fetch the record and independently confirm the new fingerprint.

If the old identity is unavailable, account recovery must be an explicit future
administrative or out-of-band process. The server must not silently replace a
device identity based only on a new public key.

## 6. Server data model

The initial single-server implementation can use SQLite. The server database
contains metadata and opaque payloads, not client private state.

### Devices

```text
device_id
address
identity_public_key
fingerprint
api_credential_hash
status
created_at
last_seen_at
```

### Bundles

```text
device_id
bundle_bytes
bundle_version
published_at
```

### Message queue

```text
server_message_id
client_message_id
sender_device_id
recipient_device_id
opaque_payload
accepted_at
expires_at
retrieved_at
acknowledged_at
```

The queue must enforce uniqueness for a suitable combination of sender,
recipient, and client message ID so retries do not create unbounded duplicate
queue entries.

### Recovery records

```text
record_id
device_id
old_fingerprint
new_fingerprint
effective_at
record_bytes
published_at
```

## 7. Message and queue semantics

The relay provides transport semantics only:

- accepted: server durably queued the payload;
- retrieved: a client fetched the payload;
- acknowledged: client confirmed receipt of the queue item.

It must not claim delivered, decrypted, displayed, or read unless a future
client protocol explicitly defines those states.

Initial queue policy:

- bounded message size;
- bounded messages per device;
- configurable expiry for undelivered messages;
- cursor-based retrieval;
- idempotent submission using the client message ID;
- explicit acknowledgement or retention timeout;
- no silent deletion before expiry or acknowledgement policy allows it.

Recommended client connection behavior:

- open the authenticated WebSocket when the UI becomes active;
- reconnect with exponential backoff after disconnects;
- persist the retrieval cursor locally so reconnects do not skip messages;
- acknowledge items only after they have been durably handed to local client
  state;
- fall back to ordinary polling after a connection failure or when background
  execution prevents a WebSocket;
- tolerate repeated events and reconnect responses without duplicating history.

The WebSocket is an event-delivery optimization over the same durable queue. A
disconnect must not delete or lose queued items. The client uses its cursor to
reconcile events after reconnecting. The server should still return an empty
HTTP page quickly when no messages are available.

Ordering should not be promised globally. Signal handles ratchet ordering and
skipped message keys; the application should process each retrieved payload
independently.

## 8. Privacy and security boundaries

The relay can observe:

- registered device identifiers;
- sender and recipient relationships;
- message sizes;
- request and queue timestamps;
- online and retrieval behavior;
- IP addresses and normal web-server metadata.

The relay must not observe:

- plaintext messages;
- private identity keys;
- Signal session state;
- chat history passwords;
- decrypted attachments.

Required protections:

- TLS with normal certificate validation;
- strict authentication and authorization;
- request and payload size limits;
- early rejection of client IDs outside the allowlist;
- per-device and per-IP rate limiting;
- queue quotas;
- replay protection for registration and control requests;
- constant-time or safe key comparison where applicable;
- privacy-conscious logging;
- no payload logging by default;
- database backup and deletion policy;
- administrative audit logging without message contents.

The server is not an anonymity system. Metadata protection, padding, batching,
and multi-hop routing are separate future work.

## 9. Public-server authentication model

Because the relay is public-facing, authentication must address two separate
problems:

1. proving that a request comes from the owner of a registered SafeChat device;
2. preventing unauthenticated users from exhausting registration, queue, or
   message resources.

### TLS

All API traffic uses HTTPS with normal platform certificate validation. The
server must not expose a plaintext production endpoint. TLS protects API
credentials and metadata in transit, but it does not replace client identity
authentication.

### Client IDs and allowlist admission

The recommended first deployment is a private relay with an explicit device
allowlist. Each client generates a random 128-bit installation/device ID. The
ID is an identifier, not a secret. The operator adds it to the relay's
allowlist and binds it to the client's public identity key, fingerprint, and
optional human-readable label.

The allowlist entry should contain:

```text
client_id
identity_public_key
fingerprint
status: pending | active | revoked
label
created_at
```

Requests for unknown, pending, or revoked IDs should be rejected immediately,
before expensive database, queue, or cryptographic work. The server still
needs basic IP-level rate limiting because an attacker can send arbitrary fake
IDs to a public endpoint.

The ID must always be checked together with the registered public identity key.
An attacker who learns a valid client ID must not be able to impersonate that
client by claiming the ID in a request.

Knowing the client ID alone must never be sufficient to connect. Use a standard
device-enrollment pattern with a separate high-entropy secret:

1. Client generates a random client ID and a random, single-use enrollment
   secret, or the administrator generates the enrollment secret for a pending
   allowlist slot.
2. The enrollment secret is delivered to the intended client through a secure
   administrative channel, such as a QR code or direct copy/paste.
3. Client submits client ID, enrollment secret, public identity key, and a
   signed server challenge.
4. Server verifies the secret and identity-key signature, consumes the secret,
   and binds the ID to the approved public key.
5. Server issues revocable session credentials for future API access.

The enrollment secret should be at least 256 bits of randomness, expire, be
single-use, and be stored only as a hash on the server. It should never be
derived from the client ID or fingerprint.

Allowlist administration can initially be a server CLI command or protected
configuration file. A future web administration API is optional and should be
protected separately from client access.

For a public multi-user service, this model can later be extended with
operator-issued, single-use enrollment tokens. Open anonymous registration
should not be the default.

This is the lightweight version of established device-enrollment patterns. More
formal alternatives are mutual TLS client certificates or OAuth 2.0 Device
Authorization Grant. Mutual TLS provides strong transport authentication but
has more difficult certificate provisioning and rotation across desktop and
mobile clients. OAuth device flow is useful when an existing identity provider
is available, but would add an external account system. The first SafeChat
relay should use one-time enrollment secrets plus identity-key challenge
signatures, without inventing a password protocol.

### Device identity proof

Registration uses a challenge-response exchange:

1. Client presents its allowlisted client ID.
2. Client presents its public identity key and requested device address.
3. Server checks the ID and public-key binding in the allowlist.
4. Server returns a fresh, short-lived challenge.
5. Client signs a domain-separated challenge containing the server name,
   client ID, requested address, public bundle hash, and expiration.
6. Server verifies the signature with the allowlisted identity key.
7. Server issues or refreshes the API session for that device.

This proves possession of the private identity key without sending it to the
server. The server must reject reused, expired, or cross-server challenges.

### API sessions

After successful registration, the server issues:

- a short-lived access token for ordinary API calls;
- a longer-lived refresh credential for obtaining new access tokens.

Only hashes of credentials are stored server-side. Clients store credentials in
their encrypted profile database. Refresh credentials must be revocable and
rotatable. Access tokens should be scoped to one device and should expire
relatively quickly.

### Signed control requests

High-impact operations should additionally carry a request signature made by
the registered identity key. The signed request should bind:

```text
SafeChat server domain
HTTP method
canonical request path
hash of canonical request body
device ID
request nonce
timestamp and expiry
```

This protects bundle replacement, recovery publication, device revocation, and
credential rotation if an access token is stolen. The server must maintain a
replay window for nonces or timestamps.

The initial implementation may require the signed request envelope for every
authenticated API operation. This is simpler to reason about for a public
relay, while access tokens can still provide session and rate-limit grouping.

### Credential and device revocation

The server needs separate revocation controls for:

- access tokens;
- refresh credentials;
- registered devices;
- invitation tokens.

Revoking a device must stop new API access while preserving the client-side
Signal semantics: existing ciphertext is still unreadable to the server, and
peers decide how to handle identity recovery or replacement records.

### Abuse controls

Public endpoints require limits independent of authentication:

- per-IP registration and login limits;
- per-device message rate limits;
- per-account and per-device queue quotas;
- maximum request, bundle, and message sizes;
- bounded cursor/page sizes;
- connection and timeout limits;
- automatic cleanup of abandoned registrations;
- generic error responses that do not leak account existence.

The service should expose operational metrics for rejected requests, queue
growth, authentication failures, and rate-limit events without logging message
contents.

## 10. Standalone server structure

The server should be a separate binary and module boundary, for example:

```text
codebase/src/bin/safechat-relay.rs
codebase/src/relay/
├── api.rs
├── auth.rs
├── database.rs
├── queue.rs
├── directory.rs
└── models.rs
```

The existing client transport interface should live separately from the HTTP
implementation so media and manual transports do not depend on server code.

## 11. Implementation phases

### Phase 1: contract and local test relay

- Define transport-neutral payloads and capabilities.
- Define API models and error responses.
- Implement an in-process relay for deterministic client tests.
- Verify two clients can publish, fetch, decrypt, and deduplicate messages.

### Phase 2: standalone HTTP service

- Add the `safechat-relay` binary.
- Implement HTTPS API routing.
- Add invite-controlled device registration and identity challenge proof.
- Add short-lived access tokens and refresh-token rotation.
- Add signed control requests and replay protection.
- Add device and credential revocation.
- Add device registration and bundle directory.
- Add durable opaque message queues.
- Add cursor-based retrieval and acknowledgements.

### Phase 3: client integration

- Implement the HTTPS transport adapter.
- Add client configuration for relay URL and approved client ID.
- Add an operator-facing allowlist enrollment workflow.
- Keep copy/paste as a working fallback transport.
- Add transport selection/configuration without changing chat commands.
- Add recovery-record publication and retrieval.

### Phase 4: operational hardening

- TLS configuration and certificate rotation.
- Rate limits, quotas, and abuse controls.
- Queue expiry and cleanup jobs.
- Metrics that exclude message contents.
- Structured privacy-safe logs.
- Backup, restore, and database migration procedures.
- Container/package/release workflow.

### Phase 5: production readiness

- Process-kill and power-loss tests.
- API fuzzing and malformed-payload tests.
- Load and queue-pressure tests.
- Authentication and authorization review.
- Dependency audit and signed releases.
- Independent security review.

## 12. Acceptance criteria for the first usable relay

- Two clients can register over HTTPS.
- Both clients require explicit server-admin allowlist approval before
  transport access.
- Allowlist entries bind client IDs to public identity keys and fingerprints.
- Clients can publish and fetch verified public bundles.
- Client A can send an opaque Signal message to client B.
- Client B can retrieve and decrypt it through the existing UI.
- The same queue item can be fetched repeatedly without creating duplicate
  history entries.
- Offline messages survive server restart.
- Clients discover new messages through an active WebSocket, with cursor-based
  HTTP polling as a reconnect/background fallback and without platform push
  services.
- Expired messages are removed according to policy.
- Recovery records can be published and fetched without server decryption.
- Invalid device signatures and unauthorized bundle updates are rejected.
- Registration, token refresh, and control requests are rate-limited and
  replay-protected.
- Stolen or revoked credentials can be invalidated without deleting unrelated
  devices.
- Server logs contain no plaintext or private-key material.
- Copy/paste and future media transports remain usable without the relay.

## 13. Explicit non-goals for the first version

- Server-side message decryption.
- Group chat.
- Read receipts.
- Guaranteed delivery semantics.
- Full anonymity or traffic-flow protection.
- Multi-server federation.
- End-to-end encrypted server-side search.
- Automatic password recovery for client profiles.

## 14. Containerized VPS deployment

The recommended initial deployment is a dedicated relay container on a remote
VPS. Container isolation reduces the blast radius of a relay compromise, but
it is defense in depth; the VPS host, kernel, Docker/container runtime, and
network configuration still require normal security maintenance.

### Container requirements

- Run as a non-root user with a fixed unprivileged UID.
- Use a minimal pinned runtime image, preferably with a pinned digest.
- Do not mount the Docker socket or host system directories.
- Use a read-only root filesystem where practical.
- Mount only the relay database, TLS material, and controlled configuration.
- Drop all Linux capabilities and add none unless a documented requirement
  appears.
- Enable `no-new-privileges`.
- Apply a restrictive seccomp/AppArmor or equivalent runtime profile.
- Set CPU, memory, process, file-descriptor, and restart limits.
- Keep temporary storage bounded and non-persistent.
- Expose only the HTTPS port.
- Separate database backups from the live container filesystem.
- Never pass private TLS keys through image layers or source control.

### VPS requirements

- Use a dedicated VPS or isolated host for the relay.
- Keep the host OS, container runtime, and kernel patched.
- Configure a host firewall with only SSH administration and the HTTPS port
  exposed.
- Use SSH keys, disable password login, and restrict administrative users.
- Do not run unrelated public services on the relay host.
- Monitor authentication failures, resource exhaustion, queue growth, and
  container restarts without logging message contents.
- Test restore procedures for the relay database and TLS configuration.

### Standalone build and release

The relay should have its own build target and release artifact, for example
`safechat-relay`, and should be runnable without building or copying the client
UI. The container image should be reproducible from a pinned source revision
and dependency lockfile. Client and relay releases should advertise compatible
HTTP API versions rather than requiring matching application binaries.
