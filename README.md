# SafeChat

SafeChat is a Rust protocol prototype using the pinned upstream Signal
implementation. Carrier adapters and steganography are separate evaluation
components; no custom cryptographic protocol is shipped.

Architecture and roadmap: [docs/PROJECT_PLAN.md](docs/PROJECT_PLAN.md)

Signal dependency policy: [docs/SIGNAL_INTEGRATION.md](docs/SIGNAL_INTEGRATION.md)

## Run the current implementation

Build the development image and run the official Signal session smoke test:

```sh
docker compose build rust-dev
docker compose run --rm rust-dev cargo run --locked -- signal-demo
```

The Compose setup persists Cargo's registry and Git caches in named Docker
volumes, so Rust crates and the pinned libsignal source are fetched only on the
first build. Keep using the commands below; the caches survive `--rm`
containers and image rebuilds. Cargo may still check the crates.io index, but it
does not redownload already cached dependencies.

The demo creates two SQLite-backed local devices, initializes a session from a
prekey bundle, encrypts/decrypts messages through libsignal, and verifies that
the session survives a restart.

Run tests and strict linting:

```sh
docker compose run --rm rust-dev cargo test --locked
docker compose run --rm rust-dev cargo clippy --locked --all-targets --all-features -- -D warnings
```

Build a standalone Linux binary:

```sh
docker compose run --rm rust-dev cargo build --release --locked
./codebase/target/release/safechat --help
```

## Friendly manual-chat UI

Build and run the separate interactive UI:

```sh
docker compose run --rm rust-dev cargo run --locked --bin safechat-ui
```

It guides first-time setup, displays public bundles and outgoing ciphertext in
the UI for copy/paste, and unlocks both the encrypted chat history and the
SQLCipher-encrypted Signal identity database with the profile password.
Communication does not use plaintext, bundle, or ciphertext files. Each
trusted participant is an independent private lobby with its own pairwise
Signal session and encrypted history.
At login, the first option shows copyable encrypted chat (ciphertext); the
second shows clean, readable chat. Both views include UTC timestamps. During
a session, `/cipher` switches to ciphertext history and `/clean` switches to
the readable history. The profile uses the platform application-data
directory; use `--profile NAME` to keep identities separate.

After `/send`, copy the complete ciphertext shown in the UI and send it through
your separate channel. Use `/receive` and choose `Paste ciphertext` to receive
one. `/bundle` similarly displays the current public bundle for copy/paste.

Use `/add-peer` to create another private lobby, `/peers` to list participants,
and `/use NAME` to switch the active lobby. Messages are sent only to the
currently selected peer.

### Relay-backed UI

Start the UI with the allowlisted client ID and relay URL:

```sh
docker compose run --rm rust-dev cargo run --locked --bin safechat-ui -- \
  --relay-url https://relay.example \
  --relay-enrollment-secret '<one-time-secret>'
```

For a local test relay using a self-signed certificate, add
`--relay-ca-cert /path/to/ca.pem`. On first launch the UI registers the
device and stores the resulting relay session token encrypted with the
profile password. If `--relay-client-id` is omitted, the UI generates a
stable client ID from the local identity and displays the client ID, public
identity key, and fingerprint for the relay administrator to allowlist. The
UI waits for allowlisting and can retry enrollment without restarting. The
enrollment secret is not needed on later launches.

At startup, choose Copy/paste or Relay. With Relay selected, `/add-peer`
fetches a peer's public bundle from the relay and confirms its fingerprint.
Relay mode behaves like a normal messenger: type ordinary text to encrypt and
send it, while the UI checks for and displays incoming messages automatically.
`/s` and `/send` remain available as explicit send aliases, and `/r` and
`/receive` remain available for manual polling. Use `/transport` to view or
change the active mode. `/r <ciphertext>` always remains available for manual
decryption.

Each UI message carries a random authenticated message ID. It is not shown as
chat content, but it prevents the same logical message from being inserted
into a lobby history more than once.

Relay messages are timestamped in live output and encrypted history. Outgoing
relay messages show `[sent]` after the relay accepts them; this means the
server has queued the message, not that the recipient has opened it. Incoming
messages are acknowledged by the recipient and shown with their receive
timestamp.

Transport implementations use a shared carrier-neutral message boundary. The
relay adapter is the first network implementation; future P2P and media
carriers can transport the same already-encrypted envelope without changing
Signal sessions, message history, or chat commands.

Use `/keys` for local prekey inventory and rotation diagnostics. If the device
identity is compromised or must be replaced, use `/replace-identity`; this
revokes current sessions, displays a new fingerprint and bundle, and emits a
signed recovery record for existing peers. Existing peers paste that record
with `/accept-recovery` and confirm the new fingerprint through their separate
trusted channel. `/revoke-device` locally revokes the active peer device and
requires fresh verification before it can be used again.

Use `/keys` to see persistent maintenance-failure counts and the last error;
repeated replenishment or rotation failures are shown as an alert.

For copy/paste chat, use the shortcuts directly at the prompt:

```text
/s hello Bob
/r safechat-text-v1:...
```

In copy/paste mode, `/s` prints the ciphertext in the chat and `/r` prints the
decrypted message. In relay mode, ordinary text is the normal send action.

The release archives contain both `safechat` and `safechat-ui` binaries.

## Standalone relay server

The relay is an independent Cargo package and does not depend on the client UI
or client profile database. Build it with:

```sh
docker compose run --rm rust-dev cargo build --release --locked -p safechat-relay
```

For the recommended public deployment, set a DNS name pointing to the VPS,
then let Caddy handle HTTPS and certificate renewal:

```sh
export SAFECHAT_RELAY_HOSTNAME=relay.example.com
export SAFECHAT_RELAY_ADMIN_TOKEN='<high-entropy-admin-token>'
docker compose -f docker-compose.relay.yml pull
docker compose -f docker-compose.relay.yml up -d
```

The Compose deployment pulls the prebuilt relay image from GHCR, so the VPS
does not need a Rust toolchain or a local compilation step. For a private
GHCR package, authenticate Docker on the VPS first:

```sh
docker login ghcr.io
```

Caddy publishes port 8443 for HTTPS and port 80 for ACME certificate
issuance/renewal. Clients should use `https://relay.example.com:8443`. The
relay runs without a published host port on a private Docker network. Native
relay TLS remains available when running `safechat-relay` outside this Compose
deployment.

See [`codebase/relay/README.md`](codebase/relay/README.md) and
[`docs/RELAY_SERVER_PLAN.md`](docs/RELAY_SERVER_PLAN.md) for enrollment and
deployment details.

The low-level `safechat signal ...` commands also prompt for the encrypted
database password. Existing plaintext `identity.db` files are rejected and
must be migrated before use; they are never silently overwritten.

For text-only transports, the UI displays URL-safe Base64 ciphertext; this does
not replace encryption or authentication.

## Other current commands

The CLI also exposes protocol validation and detector commands:

```text
safechat signal-demo
safechat inspect <PNG>
safechat detect --reference <clean.png> --candidate <candidate.png>
safechat blind-detect <PNG> --window-bits 1024 --threshold 0.05
safechat benchmark --clean-dir <dir> --encoded-dir <dir>
```

Carrier writing and transport integrations are developed as separate adapters.

## Release binaries

Push a version tag from a commit on `main` to build Linux, Windows, and macOS
release archives, publish the relay image to GHCR, and attach the binaries to
a GitHub release:

```sh
git tag v0.2.2
git push origin v0.2.2
```

The relay image is published as
`ghcr.io/chelyabinsk/safechat-relay:<version>` and `:latest`.

The workflow runs only for `v*` tags and rejects tags that do not point to a
commit reachable from `main`.

## Repository layout

- `codebase/core/` — Signal protocol, domain types, transport/history ports, and encrypted storage
- `codebase/application/` — UI-independent chat use cases and event orchestration
- `codebase/transports/` — relay and future P2P/media transport adapters
- `codebase/src/` — terminal UI and standalone protocol/detector tools
- `codebase/relay/` — standalone relay server, independent of the client crates
- `codebase/src/carrier.rs` — carrier abstraction and evaluation PNG adapter
- `docs/` — design, protocol, and operational documentation

The detector is a benchmark, not a security claim. Its baseline recognizes the
current evaluation carrier behavior and must be calibrated against disjoint,
representative corpora.
