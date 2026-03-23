# keymod

Rust WASM modules for Arysen agent cryptography, credential management, and mandate enforcement. Two crates compile to WebAssembly via wasm-pack and are consumed by [`agent-sdk`](../agent-sdk).

## Crates

### `arysen-wallet`

Dual-scheme cryptographic signing:

- **Ed25519** — Worker key for agent identity and API request signing
- **secp256k1 ECDSA** — Session key for EVM-compatible transaction signing

Features:
- Keypair generation with derived key IDs (`sha256(pubkey)[:16]`)
- In-memory key store for WASM instance lifetime
- AES-256-GCM encryption utilities for key material
- `_with_secret()` exports for cross-module key sharing

### `arysen-mandate`

Policy-enforced credential injection and transaction orchestration:

- **Secret vault** — Store and retrieve secrets encrypted in WASM memory (AES-256-GCM). Values never leave the module in plaintext.
- **Credential injection** — `{PLACEHOLDER}` substitution in HTTP request templates with automatic response scrubbing.
- **Policy engine** — Spending limits (per-tx, daily, expiry), secret rate-limiting, domain allowlists.
- **Backend communication** — Authenticated API calls with Ed25519-signed `X-ARYSEN-*` headers.
- **Transaction flow** — 5-step pipeline: local pre-flight → backend check-spend → prepare → session-key signing → submit.

## Prerequisites

- [Rust](https://rustup.rs/) with `wasm32-unknown-unknown` target
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)

```bash
rustup target add wasm32-unknown-unknown
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
```

## Build

```bash
# Native tests
cargo test

# WASM modules (scoped npm packages: @arysenai/*)
cd wallet && wasm-pack build --target nodejs --scope arysenai && cd ..
cd mandate && wasm-pack build --target nodejs --scope arysenai && cd ..
```

Output in `wallet/pkg/` and `mandate/pkg/`.

## Architecture

```
┌─────────────────────────────────────────────────┐
│  agent-sdk (TypeScript)                         │
│  ArysenKeymod class                             │
├────────────────────┬────────────────────────────┤
│  arysen-wallet     │  arysen-mandate            │
│  (WASM)            │  (WASM)                    │
│                    │                            │
│  Ed25519 sign      │  SecretVault               │
│  secp256k1 sign    │  PolicyEngine              │
│  Key store         │  Credential injection      │
│                    │  signed_fetch → Backend     │
│                    │  transfer_usdc / deal_order │
│                    │                            │
│                    │  depends on arysen-wallet   │
│                    │  (statically linked)        │
└────────────────────┴────────────────────────────┘
         ↕ Host imports (env)
┌─────────────────────────────────────────────────┐
│  Node.js / Wassette runtime                     │
│  key_store_read/write, get_time, http_execute   │
└─────────────────────────────────────────────────┘
```

## WASM Exports

### Wallet

| Export | Description |
|--------|-------------|
| `generate_worker_keypair()` | Ed25519 keypair → `{pub_key, key_id}` |
| `generate_worker_keypair_with_secret()` | Includes `private_key` |
| `generate_session_keypair()` | secp256k1 keypair → `{pub_key, key_id}` |
| `generate_session_keypair_with_secret()` | Includes `private_key` |
| `sign_worker(message, key_id)` | Ed25519 signature (64 bytes) |
| `sign_session(message, key_id)` | secp256k1 signature (65 bytes) |
| `verify_worker(message, sig, pub_key)` | Ed25519 verify |
| `verify_session(message, sig, pub_key)` | secp256k1 verify |

### Mandate

| Export | Description |
|--------|-------------|
| `deposit_secret(name, value)` | Store encrypted secret |
| `remove_secret(name)` | Delete secret |
| `list_secret_names()` | List names (no values) |
| `execute_request(template_json)` | Credential-injected HTTP |
| `set_policy(policy_json)` | Configure spending/rate limits |
| `check_policy(action, params_json)` | Check if action is allowed |
| `get_spending_summary()` | Usage stats |
| `mandate_init(config_json)` | Initialize with backend |
| `get_mandate_info()` | Cached mandate details |
| `transfer_usdc(to, amount)` | USDC transfer (5-step flow) |
| `create_deal_order(params_json)` | Escrowed deal order |

> **Note:** WASM binary hashes are computed at load time by the agent-sdk (`computeWasmHash`), not inside WASM. See `agent-sdk/src/keymod/loader.ts`.

## Tests

125 tests across unit and integration suites:

```
wallet lib:         19 tests
wallet integration:  9 tests
mandate lib:        64 tests
mandate integration: 33 tests
```
