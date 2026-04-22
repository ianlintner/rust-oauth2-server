#!/usr/bin/env bash
set -euo pipefail

include_mongo_variants=0

usage() {
  cat <<'USAGE'
Usage: .github/scripts/build_release_binaries.sh [--include-mongo-variants]

Builds release binaries for linux/amd64 and linux/arm64.

Options:
  --include-mongo-variants  Also build the `mongo` and `mongo-only` variants.
  -h, --help                Show this help text.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --include-mongo-variants)
      include_mongo_variants=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

require cargo
require cross

build_variant() {
  local label="$1"
  local suffix="$2"
  shift 2
  local cargo_args=("$@")

  echo "==> Building ${label} (linux/amd64)"
  cargo build --release --locked "${cargo_args[@]}"
  test -f target/release/rust_oauth2_server
  cp target/release/rust_oauth2_server "target/release/rust_oauth2_server${suffix}-amd64"

  echo "==> Building ${label} (linux/arm64)"
  cross build --release --locked --target aarch64-unknown-linux-gnu "${cargo_args[@]}"
  test -f target/aarch64-unknown-linux-gnu/release/rust_oauth2_server
  mkdir -p target/release
  cp \
    target/aarch64-unknown-linux-gnu/release/rust_oauth2_server \
    "target/release/rust_oauth2_server${suffix}-arm64"
}

mkdir -p target/release

build_variant "default" ""

if [[ "${include_mongo_variants}" == "1" ]]; then
  build_variant "mongo" "-mongo" --features mongo
  build_variant "mongo-only" "-mongo-only" --no-default-features --features mongo,otel
fi

echo "==> Built release binaries"
find target/release -maxdepth 1 -type f -name 'rust_oauth2_server*' -print | sort