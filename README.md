# Rust development container

This repository includes a non-root Rust development image based on Debian Bookworm. It provides Rust, Cargo, common native build dependencies, and a host-visible Rust workspace.

The architecture and implementation roadmap are documented in [docs/PROJECT_PLAN.md](docs/PROJECT_PLAN.md).

Current protocol decisions are documented in [docs/PROTOCOL_DESIGN.md](docs/PROTOCOL_DESIGN.md).

The detectability benchmark strategy is documented in [docs/PROJECT_PLAN.md](docs/PROJECT_PLAN.md); the detector will be developed as a separate evaluation component.

Project source code belongs in `codebase/`. Docker mounts that folder at `/workspace`, so files created or edited in the container are available directly on the host.

Build the image directly:

```sh
docker build -t safechat-rust-dev .
```

Start an interactive development shell with Docker Compose:

```sh
docker compose run --rm rust-dev
```

From inside the container, normal Rust commands work as expected:

```sh
cargo test
cargo run -- --help
```

The MVP CLI supports local PNG carriers:

```sh
docker compose run --rm rust-dev cargo run -- keygen /workspace/key.txt
docker compose run --rm rust-dev cargo run -- encode \
  --input /workspace/message.txt \
  --carrier /workspace/carrier.png \
  --output /workspace/encoded.png \
  --key /workspace/key.txt \
  --context "shared-context"
docker compose run --rm rust-dev cargo run -- decode \
  --input /workspace/encoded.png \
  --output /workspace/recovered.txt \
  --key /workspace/key.txt \
  --context "shared-context"
docker compose run --rm rust-dev cargo run -- inspect /workspace/carrier.png
```

Encryption mode can be selected explicitly. Symmetric mode uses one shared key. Public mode uses a recipient key pair plus a long-term sender identity key. The image stores the sender's ephemeral encryption key, identity public key, and signature. The recipient must verify that identity key through a trusted secondary channel:

```sh
./codebase/target/release/safechat keygen \
  --mode public \
  --public-output codebase/recipient.public \
  codebase/recipient.private

./codebase/target/release/safechat keygen \
  --mode identity \
  --public-output codebase/sender.identity.public \
  codebase/sender.identity.private

./codebase/target/release/safechat encode \
  --mode public \
  --input codebase/message.txt \
  --carrier codebase/carrier-small.png \
  --output codebase/encoded-public.png \
  --recipient-public-key codebase/recipient.public \
  --sender-private-key codebase/sender.identity.private \
  --context "public-context"

./codebase/target/release/safechat decode \
  --mode public \
  --input codebase/encoded-public.png \
  --output codebase/recovered-public.txt \
  --private-key codebase/recipient.private \
  --trusted-sender-public-key codebase/sender.identity.public \
  --context "public-context"
```

Public-key mode provides hybrid encryption, recipient confidentiality, and sender authentication. The embedded identity public key is not trusted by itself; decoding requires the expected sender public key and rejects mismatches or invalid signatures. A compromised or replaced identity still requires user-managed out-of-band rotation.

The initial Signal-like handshake establishes a shared session key. Verify identity fingerprints through your separate secure channel before accepting them:

~~~sh
safechat keygen --mode public --public-output recipient.public recipient.private
safechat keygen --mode public --public-output recipient.prekey.public recipient.prekey.private
safechat keygen --mode identity --public-output recipient.identity.public recipient.identity.private
safechat prekey-cert --recipient-public-key recipient.public --prekey-public-key recipient.prekey.public --identity-private-key recipient.identity.private --output recipient.prekey.cert
safechat keygen --mode identity --public-output sender.identity.public sender.identity.private
safechat fingerprint sender.identity.public

safechat handshake-init --output handshake.txt --session-output sender.session \
  --recipient-public-key recipient.public \
  --recipient-identity-public-key recipient.identity.public \
  --recipient-prekey-public-key recipient.prekey.public \
  --recipient-prekey-certificate recipient.prekey.cert \
  --sender-identity-private-key sender.identity.private

safechat handshake-accept --input handshake.txt --output recipient.session \
  --recipient-private-key recipient.private \
  --recipient-prekey-private-key recipient.prekey.private \
  --recipient-identity-private-key recipient.identity.private \
  --trusted-sender-identity-public-key sender.identity.public
~~~

This is a custom, versioned X3DH-like bootstrap. It is not interoperable with Signal and does not yet include Double Ratchet message keys, persistent replay state, or post-compromise recovery. The resulting session files can be supplied to symmetric text encoding and decoding with --key.

The carrier-independent text mode uses the same encryption and authentication but writes a URL-safe textual envelope instead of modifying an image. It is useful for testing the communication protocol and sending ordinary chat messages, but it does not provide steganographic cover:

```sh
./codebase/target/release/safechat text-encode \
  --mode public \
  --input codebase/message.txt \
  --output encrypted-message.txt \
  --recipient-public-key codebase/recipient.public \
  --sender-private-key codebase/sender.identity.private \
  --context "public-context"

./codebase/target/release/safechat text-decode \
  --mode public \
  --input encrypted-message.txt \
  --output recovered-text.txt \
  --private-key codebase/recipient.private \
  --trusted-sender-public-key codebase/sender.identity.public \
  --context "public-context"
```

The text output begins with `safechat-text-v1:` and is URL-safe Base64, so it can be copied through a chat transport without binary data handling. The text mode currently has the same message-size limitations as the underlying MVP envelope.

The Rust implementation keeps this split explicit: `codebase/src/transport.rs` owns the reference text transport, while `codebase/src/carrier.rs` defines the carrier adapter boundary and contains the initial `PngCarrier`. Future GIF, audio, and video support should implement that boundary without changing the authenticated protocol or text transport.

The reference-pair detector benchmark compares a clean carrier with an encoded candidate:

```sh
./codebase/target/release/safechat detect \
  --reference codebase/carrier-small.png \
  --candidate codebase/encoded.png
```

This first detector is an oracle benchmark because it has the original carrier. It measures changed RGB LSBs and is not yet a blind detector.

The experimental blind baseline uses only the candidate image:

```sh
./codebase/target/release/safechat blind-detect \
  codebase/encoded-benchmark.png \
  --window-bits 512 \
  --threshold 0.05
```

The threshold is not calibrated for production use. In the current experiment, the tiny 47-byte payload was not flagged, while a 520-byte payload was flagged. This is a development benchmark for finding the embedding method's operating boundary.

The corpus benchmark fits a threshold over clean and encoded directories:

```sh
./codebase/target/release/safechat benchmark \
  --clean-dir /path/to/clean-pngs \
  --encoded-dir /path/to/encoded-pngs \
  --window-bits 512
```

Its accuracy is only meaningful with a representative corpus and disjoint evaluation data. The current local result uses two clean and two encoded samples and is therefore exploratory only.

The key file and message/carrier files are in `codebase/` on the host because Docker mounts that directory at `/workspace`. This MVP intentionally supports PNG only; GIF, audio, video, richer key exchange, and error correction are future adapters/features.

The sample application lives in `codebase/`. That directory is mounted at `/workspace`, so its Rust source files are available on the host at `codebase/src/main.rs` and can be edited there. Set `UID` and `GID` when building through Compose if the host user is not `1000`:

```sh
UID=$(id -u) GID=$(id -g) docker compose build
```

Git is initialized at the project root, so use normal Git commands from the repository root:

```sh
git status
git add .
git commit -m "Initial project"
```
