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
