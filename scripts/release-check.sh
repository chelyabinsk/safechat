#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

fail() {
    printf 'release-check: error: %s\n' "$1" >&2
    exit 1
}

printf '== Checking release workflow syntax ==\n'
if command -v actionlint >/dev/null 2>&1; then
    actionlint .github/workflows/*.yml
else
    printf 'release-check: actionlint is not installed; skipping workflow lint\n'
    printf '  Install it from https://github.com/rhysd/actionlint\n'
fi

printf '\n== Checking locale files ==\n'
python3 - <<'PY'
import json
from pathlib import Path

locale_dir = Path("codebase/slint-ui/locales")
for name in ("en.json", "ru.json"):
    path = locale_dir / name
    if not path.is_file():
        raise SystemExit(f"missing locale file: {path}")
    with path.open(encoding="utf-8") as handle:
        json.load(handle)
    print(f"valid: {path}")
PY

command -v docker >/dev/null 2>&1 || fail "Docker is required for the reproducible Rust build"
docker compose version >/dev/null 2>&1 || fail "Docker Compose is required"

printf '\n== Running Rust tests ==\n'
docker compose run --rm rust-dev cargo test --locked

printf '\n== Building release binaries ==\n'
docker compose run --rm rust-dev cargo build --release --locked
docker compose run --rm rust-dev cargo build --release --locked -p safechat-slint-ui

release_dir="$repo_root/codebase/target/release"
for binary in safechat safechat-ui safechat-slint-ui; do
    test -x "$release_dir/$binary" || fail "missing Linux release binary: $release_dir/$binary"
done

printf '\n== Checking Linux archive contents ==\n'
archive_dir=$(mktemp -d)
trap 'rm -rf "$archive_dir"' EXIT
cp -R "$release_dir/locales" "$archive_dir/locales" 2>/dev/null || true
if [[ ! -f "$archive_dir/locales/en.json" || ! -f "$archive_dir/locales/ru.json" ]]; then
    cp -R codebase/slint-ui/locales "$archive_dir/locales"
fi
tar -czf "$archive_dir/safechat-linux.tar.gz" \
    -C "$release_dir" safechat safechat-ui safechat-slint-ui \
    -C "$archive_dir" locales
tar -tzf "$archive_dir/safechat-linux.tar.gz" | grep -Fxq 'locales/en.json' || fail "Linux archive is missing locales/en.json"
tar -tzf "$archive_dir/safechat-linux.tar.gz" | grep -Fxq 'locales/ru.json' || fail "Linux archive is missing locales/ru.json"
printf 'valid: Linux archive contains binaries and locales\n'

printf '\n== Checking Flatpak prerequisites ==\n'
if command -v flatpak-builder >/dev/null 2>&1 && command -v flatpak >/dev/null 2>&1; then
    flatpak info org.freedesktop.Platform//24.08 >/dev/null 2>&1 \
        || fail "Freedesktop Platform 24.08 is not installed"
    flatpak info org.freedesktop.Sdk//24.08 >/dev/null 2>&1 \
        || fail "Freedesktop SDK 24.08 is not installed"
    flatpak info org.freedesktop.Sdk.Extension.rust-stable//24.08 >/dev/null 2>&1 \
        || fail "Rust SDK extension 24.08 is not installed"
    printf 'valid: Flatpak tooling and runtimes are installed\n'
else
    printf 'release-check: flatpak-builder/flatpak is not installed; skipping local Flatpak build\n'
    printf '  Install Flatpak tooling and runtimes before validating Flatpak locally.\n'
fi

printf '\nrelease-check: all available checks passed\n'
