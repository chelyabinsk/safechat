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

## Two-user Signal example

The lifecycle is: initialize each local device once, export Bob's public
bundle, verify/trust Bob's fingerprint on Alice, then encrypt and decrypt
messages using the persistent databases.

Initialize Alice and Bob:

```sh
docker compose run --rm rust-dev cargo run --locked -- signal init \
  --database /workspace/alice.db --user alice
docker compose run --rm rust-dev cargo run --locked -- signal init \
  --database /workspace/bob.db --user bob
```

Export Bob's bundle and note the printed fingerprint:

```sh
docker compose run --rm rust-dev cargo run --locked -- signal bundle \
  --database /workspace/bob.db --output /workspace/bob.bundle
```

For a text-only channel, add `--base64` to `signal bundle` and `signal trust`.
The output is prefixed with `safechat-bundle-v1:` and remains a public bundle;
verify its fingerprint through the separate trusted channel before trusting it.

Alice also exports her bundle so Bob can verify Alice before accepting her
messages:

```sh
docker compose run --rm rust-dev cargo run --locked -- signal bundle \
  --database /workspace/alice.db --output /workspace/alice.bundle
```

On Alice's device, trust that bundle only after comparing its fingerprint
through the separate trusted channel:

```sh
docker compose run --rm rust-dev cargo run --locked -- signal trust \
  --database /workspace/alice.db --bundle /workspace/bob.bundle \
  --fingerprint <verified-bob-fingerprint>
```

On Bob's device, verify Alice's printed fingerprint through the same trusted
channel and trust Alice's bundle:

```sh
docker compose run --rm rust-dev cargo run --locked -- signal trust \
  --database /workspace/bob.db --bundle /workspace/alice.bundle \
  --fingerprint <verified-alice-fingerprint>
```

Alice can now send Bob a message:

```sh
docker compose run --rm rust-dev cargo run --locked -- signal encrypt \
  --database /workspace/alice.db --bundle /workspace/bob.bundle \
  --input /workspace/alice.txt --output /workspace/message.ciphertext
```

Bob decrypts it:

```sh
docker compose run --rm rust-dev cargo run --locked -- signal decrypt \
  --database /workspace/bob.db --sender alice \
  --input /workspace/message.ciphertext --output /workspace/bob.txt
```

The database files preserve identity, trust, prekeys, and session state.
Repeat only `signal encrypt` and `signal decrypt` for subsequent messages.

## Friendly manual-chat UI

Build and run the separate interactive UI:

```sh
docker compose run --rm rust-dev cargo run --locked --bin safechat-ui
```

It guides first-time setup, writes public bundles and outgoing ciphertext to
the profile's `outbox/` directory, accepts incoming ciphertext from a file or
paste, and displays chat history after unlocking it with the profile password.
At login, the first option shows copyable encrypted chat (ciphertext); the
second shows clean, readable chat. Both views include UTC timestamps. During
a session, `/cipher` switches to ciphertext history and `/clean` switches to
the readable history. The profile uses the platform application-data
directory; use `--profile NAME` to keep identities separate.

After `/send`, the complete ciphertext is printed in the terminal as well as
saved in `outbox/`. To receive a message, choose `Type or paste ciphertext`
first and press Enter after pasting the single-line ciphertext. File input is
the second option.

For quick manual chat, use the shortcuts directly at the prompt:

```text
/s hello Bob
/r safechat-text-v1:...
```

`/s` prints the ciphertext in the chat; `/r` prints the decrypted message.

The release archives contain both `safechat` and `safechat-ui` binaries.

For text-only transports, add `--base64` to both commands. This wraps the
binary Signal envelope in URL-safe Base64; it does not replace encryption or
authentication. Without the flag, ciphertext files are binary.

## Other current commands

The CLI also exposes protocol validation and detector commands:

```text
safechat signal-demo
safechat inspect <PNG>
safechat detect --reference <clean.png> --candidate <candidate.png>
safechat blind-detect <PNG> --window-bits 1024 --threshold 0.05
safechat benchmark --clean-dir <dir> --encoded-dir <dir>
```

Carrier writing and transport integrations are deliberately not enabled yet.

## Release binaries

Push a version tag from a commit on `main` to build Linux, Windows, and macOS
release archives and attach them to a GitHub release:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The workflow runs only for `v*` tags and rejects tags that do not point to a
commit reachable from `main`.

## Repository layout

- `codebase/` — Rust source and Cargo manifest, mounted into Docker at `/workspace`
- `codebase/src/signal_adapter.rs` — SafeChat boundary around upstream libsignal
- `codebase/src/carrier.rs` — carrier abstraction and evaluation PNG adapter
- `codebase/src/transport.rs` — carrier-neutral text reference transport
- `docs/` — design, protocol, and operational documentation

The detector is a benchmark, not a security claim. Its baseline recognizes the
current evaluation carrier behavior and must be calibrated against disjoint,
representative corpora.
