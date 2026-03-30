#!/usr/bin/env bash
set -euo pipefail

# working dir inside container
cd /usr/src/app

BIN=target/x86_64-unknown-linux-musl/release/OpenNeutron

if [ ! -x "$BIN" ]; then
  echo "Binary not found, building for x86_64-unknown-linux-musl..."
  cargo build --release --target x86_64-unknown-linux-musl
else
  echo "Binary exists, skipping build."
fi

# Always run the app with local config file (mounted or default)
exec "$BIN"
