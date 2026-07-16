# E2EE v2 Remaining Work — Time Estimate

Date: 2026-07-16 (updated after Windows MSVC green)  
Assumption: **1 full-time engineer**; Windows = VS2022 + Rust 1.97 MSVC + Flutter 3.19 + Node.

## Progress snapshot

| Phase | Status | Notes |
|-------|--------|--------|
| **A** Badge | **Done** | Client `0.2.141+111` |
| **B** `voce-e2ee-core` | **Done** | Tests 7/7; DLL FFI smoke; WASM `pkg/`; license audit |
| **C** Server v2 enforcement | **~40%** | v1 APIs + `e2e_protocol_ver`; **new** `E2E_UPGRADE_REQUIRED` when ver≥2; device-link still missing |
| **D1** Web DM v2 | **0%** | Still `E2E_VER = 1` |
| **D2** Flutter DM v2 | **0%** | Still Dart v1; DLL ready to link |
| **D3** Channel SK + files v2 | **0%** | |
| **D4** Device link + safety UI | **0%** | |
| **D5** Docs / cutover | **0%** | |

## Effort remaining (engineer-days)

| Workstream | Optimistic | Likely | Pessimistic |
|------------|------------|--------|-------------|
| **B leftover** (none) | 0 | **0** | 0 |
| **C finish** (device-link, identity sig required, admin cutover docs) | 1d | **2d** | 3d |
| **D1** Web WASM/FFI bind + DM v2 + v1 read-only | 2.5d | **4d** | 6d |
| **D2** Flutter FFI + DM v2 + secure key store | 2d | **3.5d** | 5d |
| **D3** Channel SK + encrypted file meta | 2d | **4d** | 6d |
| **D4** Safety number + device link QR + backup UI | 2.5d | **5d** | 8d |
| **QA** cross-client + migration | 1.5d | **3d** | 5d |
| **Docs / cutover** | 0.5d | **1d** | 1.5d |

### Totals (remaining)

| Scenario | Engineer-days | Calendar (1 FTE) |
|----------|---------------|------------------|
| Optimistic | ~12d | **~2.5 weeks** |
| **Likely** | **~22.5d** | **~4.5 weeks** |
| Pessimistic | ~34.5d | **~7 weeks** |

2 engineers (Web∥Flutter after B): calendar **~3.5–4 weeks** likely.

## Critical path (updated)

```text
B ✅ → C device-link + cutover
     → D1 Web DM v2  ┐
     → D2 Flutter    ┴→ D3 → D4 → QA → set e2e_protocol_ver=2
```

## Phase B closed on this machine

- Rust **1.97.0** + VS2022 MSVC
- `cargo test -p voce-e2ee-core` green
- `scripts/ffi-smoke.ps1` OK
- `scripts/build-wasm.ps1` → `pkg/voce_e2ee_core_bg.wasm`
- Server: `E2E_UPGRADE_REQUIRED` when `e2e_protocol_ver ≥ 2`

## Next slice (Phase C/D)

1. Flutter: load `voce_e2ee_core.dll` + `voce_e2ee_call("version")` in app
2. Web: import `pkg/` WASM in `e2e` bootstrap
3. Device-link API stubs on server
