# voce-e2ee-core

Shared Rust crate for VoceChat **E2EE v2** (X3DH + Double Ratchet + Sender Keys).

## Status

**Phase B spike** — envelope types and crate layout only. Crypto primitives are added after dependency/license audit.

## Build targets

| Target | Tooling |
|--------|---------|
| Native / FFI | `cargo build -p voce-e2ee-core` |
| Web WASM | `wasm-pack build --target web` (script TBD) |

## Design

See `vocechat-client-uu/docs/superpowers/specs/2026-07-16-badge-and-e2ee-v2-design.md`.

## License

MIT — crypto dependencies will be documented before integration.
