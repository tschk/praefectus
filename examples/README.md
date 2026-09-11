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

There is no `execute` example. Trusted hosts execute through the library with an injected `Ed25519AuthorityVerifier`.

## Directory Structure

```
examples/
├── README.md
└── capabilities.rs
```
