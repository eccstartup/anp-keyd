#!/bin/bash
# Regression for shared signing/fixture orchestration. NOT macOS OS/UI evidence.
set -euo pipefail
if [ "$(id -u)" != 0 ] || [ "$(uname -s)" != Linux ] || [ ! -f /.dockerenv ]; then
  echo 'Disposable Linux root Docker only' >&2
  exit 1
fi
export CARGO_TARGET_DIR=/tmp/keyd-signing-target
export RUST_LOG=info
for account in signing-admin signing-agent; do
  useradd --create-home --shell /bin/sh "$account"
done
cargo build --locked
cargo build --locked --release --example local-preview-fixture
python3 deploy/linux/install.py --binary "$CARGO_TARGET_DIR/debug/anp-keyd" \
  --sha256 "$(sha256sum "$CARGO_TARGET_DIR/debug/anp-keyd" | cut -d' ' -f1)" \
  --allow-development-build --admin-user signing-admin --agent-user signing-agent
python3 deploy/macos/test-runtime.py --container-regression \
  --binary /usr/local/libexec/anp-keyd --config /etc/anp-keyd/service.json \
  --signing-helper "$CARGO_TARGET_DIR/release/examples/local-preview-fixture" \
  --helper-sha256 "$(sha256sum "$CARGO_TARGET_DIR/release/examples/local-preview-fixture" | cut -d' ' -f1)"
