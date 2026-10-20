# Praefectus for Hermes

This native Hermes plugin registers `praefectus_execute`, `praefectus_observe`, `praefectus_status`, and `praefectus_capabilities` through `ctx.register_tool`. It never accepts authority, keys, signatures, or authority paths in tool arguments.

Set `PRAEFECTUS_BIN` when `praefectus` is not on `PATH`. To enable the host bridge, set `PRAEFECTUS_HOST_EXECUTOR` to its executable. The plugin invokes it without a shell and writes one JSON object to standard input. Semantic execution uses `{"operation":"execute","request":{...}}`; visual capture uses `{"operation":"observe","request":{...}}`. A missing or failed bridge returns `host_executor_unavailable` with `retry_safe: false` because a transport failure cannot prove whether a dispatch or capture occurred.

The bridge returns one Praefectus JSON envelope on standard output and exits zero only after producing it.

For `praefectus_execute`, the request contains only `operation_id`, `action`, observation-fenced element `target`, `interaction_mode`, `deadline_at_ms`, `verification`, `verification_version`, and `safety`. The bridge supplies host subject/session and protocol fields, owns approval and atomic consumption, computes `normalized_action_hash`, signs `canonical_authority_bytes`, verifies against its pinned key, and invokes the library. The plugin never accepts or returns authority, session-isolation claims, credentials, semantic names, action payloads, or screenshot bytes on this semantic path.

`praefectus_execute` accepts the v2 proposal target `{kind:"element",target:{observation_id,generation,provenance_hash,element_id,fingerprint_hash}}` without protocol or authority fields. It preserves observation-fenced semantic `{kind:"invoke"}` and `{kind:"set_value",value}` and the existing observation-fenced `{kind:"click",button:"left",count:1,allow_coordinate_fallback:false}`. Click remains foreground and interactive-only; coordinate fallback, typing, paste, keys, hotkeys, movement, scrolling, legacy verification, and mismatched value hashes are rejected before the host bridge is invoked. Its result contains only redacted acknowledgement state, hashes, backend metadata, effect, delivery route, host-reported session isolation, requested interaction mode, and context preservation. An `outcome_unknown` result preserves `retry_safe: false`; inspect the same operation with `praefectus_status` and do not submit another operation automatically.

`praefectus_observe` accepts only `operation_id`, `interaction_mode`, `deadline_at_ms`, and `safety:"reversible"`. The host bridge must reject malformed or unknown fields, obtain a fresh `NativeExecutor::observe_coordinates` record, create a host-owned PNG path, construct a `Screenshot` `ActionRequest` with that exact coordinate snapshot and `VerificationPolicy::None`, add host subject/session and protocol versions, compute `normalized_action_hash`, sign `canonical_authority_bytes`, verify with the pinned key, and invoke the Praefectus engine. The engine performs the observation and current display-geometry and screen-content fence before capture. Pointer actions remain interactive-only; visual capture is a read-only capability gated by `screen_recording`, `coordinate_capture`, and private host state.

The bridge owns a private artifact cache keyed by `operation_id` and action hash. On a replay it returns the stored image and never dispatches capture again; an interrupted or missing artifact is an unknown outcome with `retry_safe:false`. A successful response is exactly `{"ok":true,"data":{"_multimodal":true,"content":[{"type":"text","text":"..."},{"type":"image_url","image_url":{"url":"data:image/png;base64,..."}}],"text_summary":"...","meta":{"backend":"...","width":1,"height":1,"capture_hash":"..."}}}`. The plugin accepts only PNG data URLs and bounded, whitelisted metadata. The image is returned to Hermes' multimodal tool result only; image bytes, action payloads, credentials, and backend detail are not placed in receipts, ledgers, logs, or trajectories. Hermes' trajectory normalization records `[screenshot]` instead of the image.

The capture implementation uses the public macOS ScreenCaptureKit API and fails closed without Screen Recording permission or the `screencapturekit` feature. It uses no CUA, private framework, private SPI, or caller-selected authority. This repository tests the plugin contract and Praefectus engine path; live Hermes bridge wiring and macOS Screen Recording permission still require host configuration and have not been runtime-verified here.

```sh
python3 -m venv /tmp/praefectus-hermes-venv
/tmp/praefectus-hermes-venv/bin/python -m pip install --requirement plugins/hermes/requirements-dev.txt
/tmp/praefectus-hermes-venv/bin/python -m ruff format --check plugins/hermes
/tmp/praefectus-hermes-venv/bin/python -m ruff check plugins/hermes
/tmp/praefectus-hermes-venv/bin/python -m ty check --python-version 3.10 --ignore unresolved-import plugins/hermes
/tmp/praefectus-hermes-venv/bin/python plugins/hermes/test_plugin.py
/tmp/praefectus-hermes-venv/bin/python -m compileall -q plugins/hermes
```
