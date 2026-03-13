#!/usr/bin/env bash
# Build both WASM modules and output hashes.json for backend reference.
# Usage: ./keymod/scripts/build-and-hash.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEYMOD_DIR="$(dirname "$SCRIPT_DIR")"

echo "Building wallet WASM..."
(cd "$KEYMOD_DIR/wallet" && wasm-pack build --target nodejs)

echo "Building mandate WASM..."
(cd "$KEYMOD_DIR/mandate" && wasm-pack build --target nodejs)

WALLET_HASH=$(sha256sum "$KEYMOD_DIR/wallet/pkg/arysen_wallet_bg.wasm" | cut -d' ' -f1)
MANDATE_HASH=$(sha256sum "$KEYMOD_DIR/mandate/pkg/arysen_mandate_bg.wasm" | cut -d' ' -f1)

cat > "$KEYMOD_DIR/hashes.json" <<EOF
{
  "wallet": "$WALLET_HASH",
  "mandate": "$MANDATE_HASH"
}
EOF

echo "Hashes written to $KEYMOD_DIR/hashes.json:"
cat "$KEYMOD_DIR/hashes.json"
