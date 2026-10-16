#!/bin/bash
set -euo pipefail
if [ "$(id -u)" != 0 ] || [ "$(uname -s)" != Linux ] || [ ! -f /.dockerenv ]; then
  echo 'This harness must run as root inside a disposable Docker container.' >&2
  exit 1
fi
export CARGO_TARGET_DIR=/tmp/keyd-target
export RUST_LOG=info
cargo build --locked
cargo test --locked --quiet
ANP_KEYD_DISPOSABLE_LINUX_TEST=1 cargo test --locked --test security_boundary -- --ignored
python3 deploy/linux/test-boundary.py --binary "$CARGO_TARGET_DIR/debug/anp-keyd"
