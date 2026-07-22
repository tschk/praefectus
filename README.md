# Praefectus

Praefectus 0.3 implements protocol v2 as a policy-neutral Rust library and JSON CLI for computer-use execution. Models propose strict `ActionRequest` values; the host retains planning, identity, approval, permissions, and policy ownership. The host signs one bounded `AuthorityGrant` with Ed25519, and Praefectus verifies it against a host-pinned issuer key before it claims or dispatches an operation.

The protocol provides durable at-most-once dispatch. Desktop and browser APIs are not transactional, so a crash, cancellation, or verification failure after dispatch can produce `outcome_unknown`; Praefectus never reports those cases as safely cancelled or retries them automatically.

## CLI

The CLI writes one stable JSON envelope to standard output: `{"ok":true,"data":...}` on success or `{"ok":false,"error":{"code":...,"message":...}}` on failure. Exit code `0` means success, `2` means invalid CLI usage, `3` means a protocol, observation, or serialization failure, and `1` is reserved for failure to write the JSON envelope itself. Only that last failure writes a diagnostic to standard error.

```sh
cargo run -- status --ledger ./operations.jsonl OPERATION_ID
cargo run -- capabilities
cargo run -- surfaces
cargo run -- observe
cargo run -- observe-surface SURFACE_ID
```

`observe` returns one bounded semantic accessibility snapshot from the active surface with short tags such as `e1`; a trusted host resolves a selected tag to its fully fenced `SemanticTargetRef` through the library. `surfaces` lists bounded opaque native surface references, and `observe-surface` observes one exact host-selected surface without activating it. Observation commands use a 30-second deadline and return `observation_error` with exit code `3` when observation is unavailable. `status` returns the durable terminal acknowledgement when one exists.

`execute` is intentionally unavailable in the standalone CLI because a same-user process cannot establish an independent host-authority boundary from a caller-selected file. Trusted hosts execute through the library with an injected `Ed25519AuthorityVerifier`. Screenshot bytes, typed text, clipboard contents, selectors, credentials, and backend detail are excluded from trajectory logs and plugin results.

## Library

Use `Engine<E>` with a host-selected `Executor` and `AuthorityVerifier`. Protocol v2 uses strict, versioned, unknown-field-denying request, target, acknowledgement, terminal, receipt, and verification types. A host computes the canonical action hash, atomically consumes its own approval, binds its UID/subject, session, policy generation, risk, expiry, operation ID, and hash into `AuthorityGrant`, and signs it. `Ed25519AuthorityVerifier::new` rejects invalid identifiers and duplicate issuer/key identifiers instead of choosing one key. Praefectus never owns host approval or policy ledgers. Hosts can use `CancellationToken` for cooperative cancellation and implement another executor. Engine calls the boundary-aware observation, resolution, and shared-context methods; custom executors should override them when their provider can honor cancellation or deadlines within a blocking operation. The host must isolate its ledger and observation directory from untrusted same-UID filesystem writers; user-only permissions do not create a boundary between processes already running as that user.

`NativeExecutor` is Praefectus-owned. It uses macOS Accessibility (AX), Windows UI Automation (UIA), and Linux AT-SPI2 to produce bounded semantic trees and execute actions on the active backend. All platforms expose fenced semantic `invoke` and `set_value`; `invoke` means the platform accessibility activation action and is never a pointer click. All platforms additionally expose `click`, `type_text`, `press`, `paste`, `hotkey`, `move`, and `scroll` as pointer-based input actions. Linux exposes effects only when the authenticated local X11 socket peer is a generation-bound native Xorg process, the server supplies RandR topology, and the XWAYLAND extension is absent; Wayland sessions use the xdg-desktop-portal RemoteDesktop interface for input and the Screenshot interface for capture. Windows additionally exposes one-step semantic scrolling when UIA reports the matching scroll pattern. Every semantic target binds its observation generation and expiry, backend provenance, process identity and generation, window identity, display geometry, opaque element identity, and element fingerprint. Missing, hidden, disabled, unstable, stale, ambiguous, or mismatched elements are rejected. Private state is restricted with Unix permissions or a protected current-user Windows ACL.

Browser hosts can opt into `CdpExecutor` with a host-constructed `CdpConfig`. Configuration accepts only an exact IPv4 loopback endpoint and binds one explicit target ID to a live browser PID and process generation. The implementation observes the selected page or webview's root frame through the DOM Snapshot and Accessibility domains, uses an isolated world for fixed actionability probes, and exposes fenced semantic invoke, single-step element scroll, and value actions only after a current observation supplies real display geometry. CDP invoke revalidates the exact root-frame object, document, geometry, accessibility fingerprint, and actionability immediately before one fixed object-bound native HTML activation; it never advertises or dispatches pointer click. CDP scroll requires amount `1` and `VerificationPolicy::None`, revalidates the root-frame target, geometry, exact hit target, and directional scrollability, then runs one fixed internal offset update on the resolved node. It succeeds only when that exact node reaches the intended offset; it does not send wheel input, activate a target, or fall back to caller JavaScript, an ancestor, or another DOM node. `SemanticObservation::target(tag)` is the intended short-tag selection path; CDP dispatch performs its own stricter live actionability and identity checks rather than requiring the generic conservative `route_action` helper. CDP sessions are shared-desktop by default; background invoke, scroll, and value actions require the host to construct an isolated session because the CDP executor has no native foreground or cursor sentinel. CDP configuration is library-only: it is not a CLI or model parameter, it does not accept remote endpoints, and it does not expose arbitrary JavaScript execution.

`ActionRequest.interaction_mode` is required and authority-bound. `interactive` permits the executor's advertised route. `background_only` refuses any action whose runtime capability cannot satisfy the host-selected session isolation. Capabilities report that executor-owned `session_isolation` before execution, and receipts bind it afterward. A model cannot assert that a session is isolated: `SessionIsolation` belongs to the executor configuration constructed by the host.

On a shared native desktop, only target-addressed accessibility actions are background-capable. Praefectus samples the foreground process/window, keyboard or accessibility focus, and pointer before dispatch and again afterward. A change or an unavailable sentinel makes the result `outcome_unknown`, even when target verification succeeds. `unchanged_at_boundaries` states only what those two samples observed; it does not claim continuous noninterference. Receipts report the requested interaction mode, actual session isolation, delivery route, and context-preservation result. Pointer delivery is never advertised as shared-desktop background execution.

Strong noninterference requires a host-owned isolated desktop, browser profile/process, session, container, or virtual machine. `host_isolated` records that trusted executor configuration; Praefectus does not create or coordinate those environments. CDP invoke, scroll, and value actions are background-capable only under that isolation contract. This follows the common split in the reviewed systems: exact semantic or protocol-addressed delivery can avoid activation, while dependable concurrent pointer input requires a separately owned environment.

Protocol v2 does not accept coordinate action targets, and the native and CDP backends do not capture or return screenshots. Screenshot bytes never enter requests, receipts, ledgers, trajectories, or plugin results. External visual artifacts remain host-owned and are represented, when needed outside the execution path, by bounded locators and hashes rather than embedded images.

## Protocol guarantees

- Strict protocol, action, target, and verification versions and JSON fields.
- Same operation ID and action hash replays the stored terminal result.
- Same operation ID with a different hash is rejected as a conflict.
- A durable claim without a terminal result becomes `outcome_unknown` on recovery.
- Every effect requires an observation-fenced semantic element target; unfenced and coordinate targets fail before authority consumption.
- Cached element targets are rejected when their live process, process generation, window, display, provenance, observation generation, or element fingerprint is stale.
- Cancellation and deadlines are checked before every effect and between repeated or chunked operations.
- Receipts contain hashes and backend metadata, not screenshot or action content.
- A host-supplied custom executor can report a click with `VerificationPolicy::None` only as `executed_unverified`; built-in executors reject click and never describe it as verified.
- `set_value` requires `VerificationPolicy::TargetValueHash` matching the requested value, then compares only the post-action value hash on the same fenced target.
- Requested verification that cannot prove the expected result terminates as `outcome_unknown`, never success, and is not retry-safe.

## Host bridges and plugins

The native OpenClaw and Hermes plugins are repository integrations, not members of the neutral crates.io package. They submit strict action proposals to a host-owned bridge. They do not observe the desktop or mint targets; the host must obtain a current Praefectus observation and supply its opaque fenced target. The bridge performs its host's approval/access check and atomic approval consumption, adds subject/session and protocol fields, signs and verifies the complete request with its pinned keyring, then invokes the library. It must return `retry_safe: false` for `outcome_unknown`. Authority material is never a model tool parameter.

Poke Around and Folk Around adapters may invoke Praefectus only after their existing host access and approval checks; their full and per-action approval modes remain host policy. An Omi adapter may prepare a Praefectus authority claim only after atomically consuming its UID-, generation-, and expiry-bound approval, after which an Omi host signer issues the authority. Praefectus does not implement, replace, or persist any of those host policies or approval ledgers.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo check --all-targets --all-features
cargo build --release
cargo package
```

## License

ISC. See [LICENSE](LICENSE).

## Acknowledgements

Praefectus provides its own native runtime and contains no copied code from the comparison projects reviewed during its design. See [ACKNOWLEDGEMENTS.md](ACKNOWLEDGEMENTS.md) for pinned project revisions, licenses, platform specifications, and the no-endorsement notice. Third-party Rust dependencies retain their respective licenses and copyright notices; see [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) for the locked dependency inventory.
