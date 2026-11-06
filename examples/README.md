# Praefectus Examples

This directory contains working examples demonstrating Praefectus capabilities.

## Examples

### 1. [capabilities](capabilities.rs)
Library hello: construct `Engine` with `NativeExecutor` and `DenyAuthority`, print capabilities, and read status for an unknown operation ID.

```bash
cargo run --example capabilities
```

**Demonstrates:**
- `Engine::new` with a host-selected ledger path
- `Engine::capabilities` without credentials
- `Engine::status` for an unknown operation ID (`None` when the ledger has no claim)
- Why `execute` stays library-only (`DenyAuthority` cannot authorize dispatch)

## Quick Start

```bash
cargo run --example capabilities
cargo run -- capabilities
cargo run -- surfaces
```

`capabilities` needs no desktop session. `surfaces` and `observe` use the native accessibility backend and return `observation_error` (CLI exit `3`) when observation is unavailable.

### Supervised FaceTime host

`facetime_host` is an operator-supervised macOS example using an ephemeral,
self-signed host authority. It is not an independent approval boundary or a
remote execution service. Every command requires `--approved-facetime`;
destination commands additionally require an exact entry in the process-local
`PRAEFECTUS_APPROVED_DESTINATIONS` allowlist. No destinations are supplied by
the repository. Accessibility permission is required; native input restrictions
remain unchanged.

`set-destination` retains value-hash verification. `type-destination` uses
Interactive input with no verification and never presses Return: dispatch is
not proof of input. `read-destination` checks independent native readback;
`commit-destination` requires the approved destination argument and repeats that
check before Return. Missing or mismatched hashes stop without committing.
Before invoking Call, the operator must independently confirm the committed
recipient is the approved test identity. No automatic dialing or retries occur.
Output omits element names and destination values; do not publish private
desktop observations or call links.

Run `cargo test --locked --example facetime_host` for construction/readback
regressions. These tests do not establish connected calls or media behavior.

## Directory Structure

```
examples/
├── README.md
└── capabilities.rs
```
