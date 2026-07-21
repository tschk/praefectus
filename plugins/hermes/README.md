# Praefectus for Hermes

This native Hermes plugin registers `praefectus_execute`, `praefectus_status`, and `praefectus_capabilities` through `ctx.register_tool`. It never accepts authority, keys, signatures, or authority paths in tool arguments.

Set `PRAEFECTUS_BIN` when `praefectus` is not on `PATH`. To enable execution, the Hermes host must set `PRAEFECTUS_HOST_EXECUTOR` to its bridge executable. The plugin invokes it without a shell and writes one JSON object to standard input: `{"operation":"execute","request":{...}}`. `request` is the strict action proposal: `operation_id`, `action`, an observation-fenced element `target`, `deadline_at_ms`, `verification`, `verification_version`, and `safety`; it has no protocol or target version, `subject`, `session_id`, authority, key, signature, issuer, or policy fields. The bridge must reject malformed or unknown fields, own the existing approval/access check and atomic approval consumption, then construct the full core request with host subject/session and versions, compute `normalized_action_hash`, sign the output of `canonical_authority_bytes`, perform pinned-key verification, and invoke the library. A missing or failed bridge returns `host_executor_unavailable` with `retry_safe: false` because a transport failure cannot prove that dispatch did not occur.

The bridge returns one Praefectus JSON envelope on standard output and exits zero only after producing it.

`praefectus_execute` accepts the v1 action request without protocol or authority fields. Its result contains acknowledgement state, hashes, backend metadata, and effect. Action payloads, evidence, backend errors, screenshot data, and authority material are removed. An `outcome_unknown` result includes `retry_safe: false`; inspect the same operation with `praefectus_status` and do not submit another operation automatically.

```sh
python3 plugins/hermes/test_plugin.py
python3 -m compileall -q plugins/hermes
```
