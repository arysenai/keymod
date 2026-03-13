# CLAUDE.md — keymod

Rust workspace producing two WASM modules (`arysen-wallet`, `arysen-mandate`) for agent cryptography and mandate enforcement.

## Structure

```
keymod/
├── Cargo.toml          # Workspace root (members: wallet, mandate)
├── wallet/             # Ed25519 + secp256k1 signing
│   ├── src/
│   │   ├── lib.rs      # WASM exports + in-memory key store
│   │   ├── ed25519.rs  # Ed25519 keypair/sign/verify
│   │   ├── secp256k1.rs # secp256k1 ECDSA keypair/sign/verify
│   │   ├── storage.rs  # AES-256-GCM key encryption
│   │   └── types.rs    # KeyPair, Signature
│   └── tests/
├── mandate/            # Policy engine + secrets + backend comms
│   ├── src/
│   │   ├── lib.rs      # WASM exports + static state + tx flow
│   │   ├── types.rs    # Policy, Secret, Backend, Transaction types
│   │   ├── policy.rs   # PolicyEngine — spending/rate-limit enforcement
│   │   ├── secrets.rs  # SecretVault — encrypted secret storage
│   │   ├── inject.rs   # Credential injection + response scrubbing
│   │   ├── http.rs     # HTTP execution + configurable mock
│   │   └── backend.rs  # signed_fetch with X-ARYSEN-* auth headers
│   └── tests/
```

## Build Commands

```bash
source ~/.cargo/env

# Run all tests (native)
cargo test

# Build WASM (both modules)
cd wallet && wasm-pack build --target nodejs && cd ..
cd mandate && wasm-pack build --target nodejs && cd ..
```

WASM output goes to `wallet/pkg/` and `mandate/pkg/`. These are linked by `agent-sdk` via pnpm `file:` dependencies. After rebuilding WASM, run `pnpm install` in agent-sdk to refresh hard-links.

## Key Architecture

- **Wallet**: Stateless crypto. Ed25519 for agent identity (worker key), secp256k1 for EVM transactions (session key). In-memory `KEY_STORE` persists private keys for the WASM instance lifetime.
- **Mandate**: Stateful policy sandbox. Depends on wallet crate (`arysen-wallet = { path = "../wallet" }`). Stores secrets encrypted in-memory (AES-256-GCM). Enforces spending limits and secret access policies.
- **Host imports**: Both modules declare C-ABI extern functions (`key_store_read`, `get_time`, `http_execute`, etc.). Native builds use stubs in `host_stubs` modules; WASM builds link against the JS env shim.
- **Backend communication**: `backend.rs` makes authenticated API calls via `signed_fetch()` with Ed25519 signatures. HTTP goes through `http.rs` which uses configurable mocks in native tests.

## Testing Notes

- Tests use `static Mutex<Option<T>>` for module state. Parallel test threads can race on statics — avoid asserting on static reads after init; use return values instead.
- `http.rs` has a `thread_local! MOCK_RESPONSES` system. Call `set_mock_response(url_pattern, response)` to configure, `clear_mock_responses()` to reset.
- The `reset_state()` helper in `lib.rs` tests clears all statics + mocks.

## Conventions

- `pub(crate)` for internal cross-module functions (e.g., `derive_key_id`)
- `wasm_bindgen` exports use snake_case matching Rust convention; the TS wrapper camelCases them
- WASM binary hashes are computed at SDK load time by `agent-sdk/src/keymod/loader.ts` (`computeWasmHash`), not inside WASM — avoids the bootstrapping problem of self-hashing
- USDC amounts: u64 with 6 decimal places (1 USDC = 1_000_000)
