# voce-e2ee-core

Shared Rust crate for VoceChat **E2EE v2** (X3DH + Double Ratchet + Sender Keys).

## Status

**Phase B complete** (2026-07-16)

| Gate | Result |
|------|--------|
| `cargo test -p voce-e2ee-core` | 7/7 pass (MSVC) |
| Release `cdylib` | `target/release/voce_e2ee_core.dll` |
| FFI smoke | `scripts/ffi-smoke.ps1` → `version` = `0.1.0` |
| WASM | `scripts/build-wasm.ps1` → `pkg/voce_e2ee_core_bg.wasm` |
| License audit | see table below |

## Modules

| Module | Role |
|--------|------|
| `identity` | X25519 IK + Ed25519 signing, signed prekeys, safety number |
| `x3dh` | Signal X3DH §2.2 agreement (X25519) |
| `ratchet` | Minimal Double Ratchet (DM) |
| `envelope` | v2 wire JSON + replay window |
| `ffi` | `voce_e2ee_call` / `voce_e2ee_free` + WASM `voce_e2ee_wasm_call` |

## Dependency / license audit

| Crate | License | Use |
|-------|---------|-----|
| `x25519-dalek` | BSD-3 | DH |
| `ed25519-dalek` | BSD-3 / MIT | Sign SPK |
| `aes-gcm` | Apache-2 / MIT | AEAD |
| `hkdf` / `sha2` / `hmac` | Apache-2 / MIT | KDF |
| `p256` | Apache-2 / MIT | v1 ECDH only |
| `serde` / `serde_json` | Apache-2 / MIT | Wire / FFI |
| `zeroize` | Apache-2 / MIT | Secret wipe |
| `rand` / `getrandom` | Apache-2 / MIT | RNG |
| `base64` | Apache-2 / MIT | Encoding |
| `thiserror` | Apache-2 / MIT | Errors |
| `wasm-bindgen` (optional) | Apache-2 / MIT | Web |

No GPL/AGPL crypto deps.

## Build (Windows)

```powershell
# Native DLL for Flutter FFI
powershell -File crates/voce-e2ee-core/scripts/build-windows.ps1
powershell -File crates/voce-e2ee-core/scripts/ffi-smoke.ps1

# WASM for Web
powershell -File crates/voce-e2ee-core/scripts/build-wasm.ps1
```

```bash
# Linux / WSL / macOS
cargo test -p voce-e2ee-core
cargo build -p voce-e2ee-core --release
./crates/voce-e2ee-core/scripts/build-wasm.sh
```

## FFI contract

```c
char* voce_e2ee_call(const char* method, const char* json_args);
void  voce_e2ee_free(char* p);
```

Methods: `version`, `generate_identity`, `generate_signed_prekey`, `safety_number`,
`x3dh_initiator`, `x3dh_responder`, `envelope_v2_parse`, `v1_decrypt`.

WASM: `voce_e2ee_wasm_call(method, jsonArgs)` (same JSON).

## Design

See `vocechat-client-uu/docs/superpowers/specs/2026-07-16-badge-and-e2ee-v2-design.md`.

**Next:** Phase C/D — wire Web + Flutter + server cutover (`e2e_protocol_ver=2`).
