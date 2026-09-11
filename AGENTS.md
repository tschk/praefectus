# Praefectus

Policy-neutral Rust library and JSON CLI for host-authorized computer-use execution.

## Layout

```
.
├── src/lib.rs                 # library: Engine, protocol types, NativeExecutor, CdpExecutor
├── src/main.rs                # JSON CLI binary `praefectus`
├── src/semantic.rs            # semantic observation and fenced target types
├── src/cdp.rs                 # library-only CDP executor
├── src/linux_*.rs             # Linux AT-SPI2 / input
├── src/macos_capture.rs       # optional macOS ScreenCaptureKit
├── src/windows_*.rs           # Windows UIA / ACL / capture
├── tests/                     # protocol, CLI, fencing, native, live tests
├── examples/                  # runnable library scenarios
├── plugins/openclaw/          # OpenClaw host plugin (not the crates.io package)
├── plugins/hermes/            # Hermes host plugin (not the crates.io package)
├── Cargo.toml
└── README.md
```

## Build and test

MSRV is Rust 1.88 (edition 2024).

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo check --all-targets --all-features
cargo build
cargo run --example capabilities
```

CI additionally uses `--locked` and `cargo package --locked`.

OpenClaw plugin (Bun):

```sh
cd plugins/openclaw
bun install --frozen-lockfile
bun run format
bun run lint
bun run typecheck
bun test
bun run build
```

Hermes plugin (Python):

```sh
python3 -m pip install --requirement plugins/hermes/requirements-dev.txt
python3 -m ruff format --check plugins/hermes
python3 -m ruff check plugins/hermes
python3 plugins/hermes/test_plugin.py
```

## CLI vs library

CLI path: `src/main.rs`, binary name `praefectus`. Existing commands:

- `status --ledger <path> OPERATION_ID`
- `capabilities`
- `surfaces`
- `observe`
- `observe-surface SURFACE_ID`

The CLI writes one JSON envelope to stdout: `{"ok":true,"data":...}` or `{"ok":false,"error":{"code":...,"message":...}}`. Exit `0` success, `2` usage, `3` protocol/observation/serialization, `1` envelope write failure.

Library path: `Engine::new(executor, ledger_path, authority)` in `src/lib.rs`. Trusted hosts inject `Ed25519AuthorityVerifier` and call `Engine::execute`. Observation, surface listing, and CDP configuration (`CdpConfig`, loopback-only) are library APIs. `NativeExecutor::list_surfaces`, `observe_semantic`, `observe_surface`, and `observe_coordinates` are the observation entry points.

`DenyAuthority` is the CLI verifier for `status` and `capabilities`. It cannot authorize dispatch.

## Do not invent

- Do not add, document, or demo a working `praefectus execute` CLI. `execute` is library-only and requires a host-injected trusted `AuthorityVerifier`.
- Do not invent credentials, keys, signatures, issuer IDs, authority paths, or model-facing authority parameters.
- Do not print secrets, screenshot bytes, typed text, clipboard contents, selectors, or backend-error detail.
- Do not invent remote CDP endpoints, arbitrary JavaScript execution, or CLI/model CDP configuration.
- Do not invent host approval, policy, or identity ledgers. Praefectus does not own those.
- Do not treat `outcome_unknown` as cancelled or retry-safe.
- Do not add OpenClaw or Hermes plugins to the crates.io package.
