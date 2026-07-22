# Praefectus for Hermes

This native Hermes plugin registers `praefectus_execute`, `praefectus_status`, and `praefectus_capabilities` through `ctx.register_tool`. It never accepts authority, keys, signatures, or authority paths in tool arguments.

Set `PRAEFECTUS_BIN` when `praefectus` is not on `PATH`. To enable execution, the Hermes host must set `PRAEFECTUS_HOST_EXECUTOR` to its bridge executable. The plugin invokes it without a shell and writes one JSON object to standard input: `{"operation":"execute","request":{...}}`. `request` is the strict action proposal: `operation_id`, `action`, an observation-fenced element `target`, required `interaction_mode` (`interactive` or `background_only`), `deadline_at_ms`, `verification`, `verification_version`, and `safety`; it has no protocol or target version, `subject`, `session_id`, session isolation, authority, key, signature, issuer, or policy fields. The bridge must reject malformed or unknown fields, own the existing approval/access check and atomic approval consumption, then construct the full core request with host subject/session and versions, compute `normalized_action_hash`, sign the output of `canonical_authority_bytes`, perform pinned-key verification, and invoke the library. The host alone selects and reports `shared_desktop` or `host_isolated` session isolation. A missing or failed bridge returns `host_executor_unavailable` with `retry_safe: false` because a transport failure cannot prove that dispatch did not occur.

The bridge returns one Praefectus JSON envelope on standard output and exits zero only after producing it.

`praefectus_execute` accepts the v2 proposal target `{kind:"element",target:{observation_id,generation,provenance_hash,element_id,fingerprint_hash}}` without protocol or authority fields and exactly two target-addressed semantic effects: `{kind:"invoke"}` with `{kind:"none"}` verification, or `{kind:"set_value",value}` with `{kind:"target_value_hash",sha256}` where `sha256` is the lowercase SHA-256 of the exact UTF-8 value. Caller authority or isolation fields, pointer clicks, coordinate fallback, typing, paste, keys, hotkeys, movement, scrolling, legacy verification, and mismatched value hashes are rejected before the host bridge is invoked. Its result contains acknowledgement state, hashes, backend metadata, effect, `delivery_route`, host-reported `session_isolation`, requested `interaction_mode`, and `context_preservation`. Capabilities expose only host-reported `invoke` and `set_value` background support; the plugin does not infer isolation. Action payloads, evidence, backend errors, typed text, clipboard data, semantic names and IDs, screenshot data, and authority material are removed. An `outcome_unknown` result includes `retry_safe: false`; inspect the same operation with `praefectus_status` and do not submit another operation automatically.

```sh
python3 -m venv /tmp/praefectus-hermes-venv
/tmp/praefectus-hermes-venv/bin/python -m pip install --requirement plugins/hermes/requirements-dev.txt
/tmp/praefectus-hermes-venv/bin/python -m ruff format --check plugins/hermes
/tmp/praefectus-hermes-venv/bin/python -m ruff check plugins/hermes
/tmp/praefectus-hermes-venv/bin/python -m ty check --python-version 3.10 --ignore unresolved-import plugins/hermes
/tmp/praefectus-hermes-venv/bin/python plugins/hermes/test_plugin.py
/tmp/praefectus-hermes-venv/bin/python -m compileall -q plugins/hermes
```
