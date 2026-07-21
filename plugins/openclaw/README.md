# Praefectus OpenClaw plugin

This native OpenClaw plugin exposes `praefectus_capabilities`, `praefectus_status`, and `praefectus_execute`. It does not grant approval and never accepts authority, keys, signatures, or authority paths in a tool request.

Configure `command` when `praefectus` is not on `PATH`, optionally configure `ledger`, and configure the host-owned `hostExecutorCommand` array to enable execution. The plugin sends that command exactly one JSON object on standard input: `{"operation":"execute","request":{...}}`. `request` is the strict action proposal: `operation_id`, `action`, `target`, `deadline_at_ms`, `verification`, and `safety`; it has no versions, `subject`, `session_id`, authority, key, signature, issuer, or policy fields. The bridge must reject malformed or unknown fields, perform the host's existing approval/access check, atomically consume any approval, construct the complete core request with host subject/session and protocol versions, issue and verify the signed one-operation authority against its pinned keyring, then invoke Praefectus through the library. A missing or failed bridge returns `host_executor_unavailable` without dispatching.

The bridge returns one Praefectus JSON envelope on standard output and exits zero only after producing it. Reuse an `operation_id` to retrieve its at-most-once result; an `outcome_unknown` result is always marked `retry_safe: false` and must not be retried with a new operation ID. The plugin redacts selectors, typed text, clipboard data, authority material, screenshot data, and backend-error detail from tool results.

```sh
bun install
bun run format
bun run lint
bun run typecheck
bun test
bun run build
```
