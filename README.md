# Praefectus

Praefectus is a policy-neutral Rust protocol and executor for desktop actions. Models propose actions; a host retains planning, identity, approval, permissions, and policy ownership. The host signs one bounded `AuthorityGrant` with Ed25519, and Praefectus verifies it against a host-pinned issuer key before it claims or dispatches an operation.

The protocol provides durable at-most-once dispatch. Desktop APIs are not transactional, so a crash or cancellation after dispatch can produce `outcome_unknown`; Praefectus never reports those cases as safely cancelled or retries them automatically.

## CLI

The CLI writes one stable JSON envelope to standard output: `{"ok":true,"data":...}` on success or `{"ok":false,"error":{"code":...,"message":...}}` on failure. Exit codes are `0` success, `2` invalid CLI usage, and `3` protocol/serialization failure. Diagnostics use standard error only when JSON output itself cannot be written.

```sh
cargo run -- status --ledger ./operations.jsonl OPERATION_ID
cargo run -- capabilities
```

`execute` is intentionally unavailable in the standalone CLI because a same-user process cannot establish an independent host-authority boundary from a caller-selected file. Trusted hosts execute through the library with an injected `Ed25519AuthorityVerifier`. `status` returns the durable terminal acknowledgement when one exists. Screenshot bytes, typed text, clipboard contents, selectors, credentials, and backend detail are excluded from trajectory logs and plugin results.

## Library

Use `Engine<E>` with a host-selected `Executor` and `AuthorityVerifier`. A host creates the canonical action hash, atomically consumes its own approval, binds its UID/subject, session, policy generation, risk, expiry, operation ID, and hash into `AuthorityGrant`, and signs it. Praefectus never owns host approval or policy ledgers. Hosts can use `CancellationToken` for cooperative cancellation and implement another executor for platform-specific integration.

`NativeExecutor` is Praefectus-owned. On macOS it uses the system CoreGraphics framework for fenced coordinate click/move actions after verifying current Accessibility permission. Windows and Linux report an unavailable backend with no executable actions. It does not advertise unfenced focus-dependent typing, paste, key, scroll, value-setting, or semantic accessibility actions. Coordinate actions require a fresh (30-second) native display-topology provenance record created by `NativeExecutor::observe_coordinates`; arbitrary snapshot IDs are rejected. CoreGraphics cannot confirm delivery of a posted input event, so coordinate execution terminates as `outcome_unknown` unless a future Praefectus-owned verifier can prove the result. Element actions are rejected when missing, hidden, disabled, stale, ambiguous, or mismatched.

## Protocol guarantees

- Strict protocol version and JSON fields.
- Same operation ID and action hash replays the stored terminal result.
- Same operation ID with a different hash is rejected as a conflict.
- A durable claim without a terminal result becomes `outcome_unknown` on recovery.
- Cached element and coordinate targets are rejected when their live fingerprints or display geometry are stale.
- Cancellation and deadlines are checked before target resolution and dispatch.
- Receipts contain hashes and backend metadata, not screenshot or action content.
- Requested verification that cannot prove the expected result terminates as `outcome_unknown`, never success.

## Host bridges and plugins

The OpenClaw and Hermes plugins submit strict action proposals to a host-owned bridge. The bridge performs its host's approval/access check and atomic approval consumption, adds subject/session and protocol fields, signs and verifies the complete request with its pinned keyring, then invokes the library. It must return `retry_safe: false` for `outcome_unknown`. The bridge contract is documented in each plugin README; authority material is never a model tool parameter.

Poke Around, Folk Around, and Omi must keep their existing host-side approval/access ownership. In particular, an Omi adapter may issue a Praefectus grant only after atomically consuming the UID-, generation-, and expiry-bound Omi approval; this crate does not implement or persist that approval state.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo check --all-targets --all-features
cargo build --release
cargo package --allow-dirty
```

## License

ISC. See `LICENSE`.

## Acknowledgements

Praefectus provides its own native runtime. [rs_peekaboo](https://github.com/undivisible/rs_peekaboo), licensed under the ISC License, was evaluated during design but is not used or linked. Its surface was informed by [Peekaboo](https://github.com/openclaw/Peekaboo), licensed under the MIT License, and [Cua Driver](https://github.com/trycua/cua), licensed under the MIT License.

The action protocol and safety model were informed by the OpenAI Computer use guide, Anthropic computer use documentation, Playwright actionability checks, the W3C WebDriver stale-element model, Microsoft UI Automation, Apple Accessibility, and the XDG Desktop Portal RemoteDesktop and ScreenCast interfaces. These projects and specifications do not endorse Praefectus.

Third-party Rust dependencies retain their respective licenses and copyright notices. See `THIRD_PARTY_LICENSES.md` for the dependency inventory.
