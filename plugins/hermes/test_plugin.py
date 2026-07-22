import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch


registry = types.ModuleType("tools.registry")
setattr(registry, "tool_error", lambda message: json.dumps({"error": message}))
tools = types.ModuleType("tools")
setattr(tools, "registry", registry)
sys.modules.update({"tools": tools, "tools.registry": registry})
spec = importlib.util.spec_from_file_location(
    "praefectus_hermes", Path(__file__).with_name("__init__.py")
)
if spec is None or spec.loader is None:
    raise RuntimeError("unable to load Praefectus Hermes plugin")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)

ACTION_HASH = "a" * 64


def semantic_target():
    return {
        "kind": "element",
        "target": {
            "observation_id": "1" * 64,
            "generation": 1,
            "provenance_hash": "2" * 64,
            "element_id": "3" * 64,
            "fingerprint_hash": "4" * 64,
        },
    }


def invoke_request():
    return {
        "operation_id": "op-1",
        "action": {"kind": "invoke"},
        "target": semantic_target(),
        "interaction_mode": "interactive",
        "deadline_at_ms": 9,
        "verification": {"kind": "none"},
        "verification_version": 2,
        "safety": "reversible",
    }


def set_value_request(value="secret"):
    return {
        **invoke_request(),
        "action": {"kind": "set_value", "value": value},
        "verification": {
            "kind": "target_value_hash",
            "sha256": hashlib.sha256(value.encode()).hexdigest(),
        },
    }


def outcome_unknown(
    operation_id="op-1",
    interaction_mode="interactive",
    session_isolation="shared_desktop",
    context_preservation="not_applicable",
):
    return {
        "acknowledgements": [
            {
                "protocol_version": 2,
                "operation_id": operation_id,
                "sequence": 2,
                "action_hash": ACTION_HASH,
                "replayed": False,
                "state": {
                    "kind": "terminal",
                    "terminal": {
                        "kind": "outcome_unknown",
                        "message": "unknown outcome",
                        "receipt": {
                            "protocol_version": 2,
                            "action_name": "invoke",
                            "action_hash": ACTION_HASH,
                            "started_at_ms": 1,
                            "finished_at_ms": 2,
                            "backend": "test",
                            "fallback_chain": [],
                            "delivery_route": "target_addressed",
                            "session_isolation": session_isolation,
                            "interaction_mode": interaction_mode,
                            "context_preservation": context_preservation,
                            "effect": "unknown",
                            "before": None,
                            "after": None,
                            "warnings": [],
                        },
                    },
                },
            }
        ]
    }


def legacy_recovery(operation_id="op-1"):
    result = outcome_unknown(operation_id)
    receipt = result["acknowledgements"][0]["state"]["terminal"]["receipt"]
    receipt["action_name"] = "unknown"
    receipt["delivery_route"] = "unknown"
    receipt["session_isolation"] = "unknown"
    receipt["interaction_mode"] = "unknown"
    receipt["context_preservation"] = "unavailable"
    return result


def runtime_capabilities(platform="windows"):
    backends = {
        "macos": "praefectus-macos-ax",
        "windows": "praefectus-windows-uia",
        "linux": "praefectus-atspi2",
        "browser": "praefectus-chromium-cdp",
    }
    actions = (
        ["invoke", "scroll", "set_value"]
        if platform in ("windows", "browser")
        else ["invoke", "set_value"]
    )
    permissions = {
        "accessibility": True,
        "coordinate_capture": False,
        "private_state": True,
        "screen_recording": False,
    }
    if platform == "linux":
        permissions.update(
            {"atspi2": True, "display_geometry": True, "wayland": False, "x11": True}
        )
    elif platform == "browser":
        permissions = {
            "cdp": True,
            "coordinates": False,
            "root_frame_only": True,
            "screenshots": False,
        }
    background_support = "host_isolated_only" if platform == "browser" else "guarded"
    return {
        "platform": platform,
        "backend": backends[platform],
        "supported_actions": actions,
        "action_capabilities": [
            {
                "action": action,
                "delivery_route": "target_addressed",
                "background_support": background_support,
            }
            for action in actions
        ],
        "permissions": permissions,
        "display_geometry_hash": "a" * 64,
    }


class PluginTest(unittest.TestCase):
    def test_registration_uses_native_hermes_contract(self):
        registrations = []
        context = types.SimpleNamespace(
            register_tool=lambda **kwargs: registrations.append(kwargs)
        )
        plugin.register(context)
        self.assertEqual(
            [item["name"] for item in registrations],
            ["praefectus_execute", "praefectus_status", "praefectus_capabilities"],
        )
        self.assertTrue(all(item["toolset"] == "praefectus" for item in registrations))
        self.assertFalse(plugin.EXECUTE_SCHEMA["parameters"]["additionalProperties"])
        self.assertNotIn(
            "authority_ref", plugin.EXECUTE_SCHEMA["parameters"]["properties"]
        )
        self.assertNotIn(
            "session_isolation", plugin.EXECUTE_SCHEMA["parameters"]["properties"]
        )
        self.assertIn(
            "interaction_mode", plugin.EXECUTE_SCHEMA["parameters"]["required"]
        )
        self.assertEqual(
            plugin.EXECUTE_SCHEMA["parameters"]["properties"]["interaction_mode"],
            {"enum": ["interactive", "background_only"]},
        )

    def test_execute_sends_only_the_action_request_to_host_executor(self):
        captured = []

        def run(request):
            captured.append(request)
            return outcome_unknown()

        args = invoke_request()
        with patch.object(plugin, "_run_host_executor", run):
            result = json.loads(plugin._execute(args))
        self.assertEqual(captured[0]["operation_id"], "op-1")
        self.assertNotIn("protocol_version", captured[0])
        self.assertNotIn("authority_ref", captured[0])
        self.assertNotIn("signed_authority", captured[0])
        self.assertNotIn("session_isolation", captured[0])
        self.assertEqual(captured[0]["interaction_mode"], "interactive")
        self.assertEqual(captured[0]["verification_version"], 2)
        self.assertNotIn("secret", json.dumps(result))
        self.assertFalse(result["acknowledgements"][0]["terminal"]["retry_safe"])

    def test_execute_fails_closed_without_host_authority(self):
        with patch.dict(os.environ, {}, clear=True):
            result = json.loads(plugin._execute(invoke_request()))
        self.assertEqual(result["error"], {"code": "host_executor_unavailable"})
        self.assertFalse(result["retry_safe"])

    def test_background_mode_is_required_and_receipt_bound(self):
        request = {**invoke_request(), "interaction_mode": "background_only"}
        with patch.object(
            plugin,
            "_run_host_executor",
            return_value=outcome_unknown(
                interaction_mode="background_only",
                context_preservation="unchanged_at_boundaries",
            ),
        ) as run:
            result = json.loads(plugin._execute(request))
        run.assert_called_once_with(request)
        self.assertEqual(
            result["acknowledgements"][0]["terminal"]["receipt"]["interaction_mode"],
            "background_only",
        )

        with patch.object(plugin, "_run_host_executor", return_value=outcome_unknown()):
            self.assertEqual(
                json.loads(plugin._execute(request)),
                {"error": {"code": "praefectus_error"}, "retry_safe": False},
            )

    def test_targets_require_an_observation_fenced_element(self):
        self.assertEqual(plugin._TARGET["properties"]["kind"], {"const": "element"})
        self.assertEqual(plugin._TARGET["required"], ["kind", "target"])
        self.assertFalse(plugin._TARGET["properties"]["target"]["additionalProperties"])
        self.assertEqual(
            plugin._TARGET["properties"]["target"]["required"],
            [
                "observation_id",
                "generation",
                "provenance_hash",
                "element_id",
                "fingerprint_hash",
            ],
        )
        self.assertEqual(
            plugin._TARGET["properties"]["target"]["properties"]["generation"],
            {"type": "integer", "minimum": 1, "maximum": 9007199254740991},
        )
        self.assertEqual(
            plugin.EXECUTE_SCHEMA["parameters"]["properties"]["deadline_at_ms"],
            {"type": "integer", "minimum": 1, "maximum": 9007199254740991},
        )
        self.assertEqual(
            plugin._TARGET["properties"]["target"]["properties"]["element_id"][
                "pattern"
            ],
            "^[0-9a-f]{64}$",
        )
        invoke = plugin._ACTION["oneOf"][0]
        self.assertEqual(
            invoke, plugin._object({"kind": {"const": "invoke"}}, ["kind"])
        )
        operation_id = plugin.EXECUTE_SCHEMA["parameters"]["properties"]["operation_id"]
        self.assertEqual(operation_id["maxLength"], 256)
        self.assertIn("pattern", operation_id)
        self.assertEqual(
            plugin.STATUS_SCHEMA["parameters"]["properties"]["operation_id"],
            operation_id,
        )
        self.assertEqual(
            plugin.EXECUTE_SCHEMA["parameters"]["properties"]["verification_version"],
            {"const": 2},
        )
        self.assertFalse(plugin._SEMANTIC_TARGET["additionalProperties"])
        pairs = plugin.EXECUTE_SCHEMA["parameters"]["oneOf"]
        self.assertEqual(
            pairs[0]["properties"],
            {"action": plugin._INVOKE_ACTION, "verification": plugin._NO_VERIFICATION},
        )
        self.assertEqual(
            pairs[1]["properties"],
            {
                "action": plugin._SET_VALUE_ACTION,
                "verification": plugin._VALUE_VERIFICATION,
            },
        )

    def test_rejects_authority_legacy_actions_and_mismatched_verification_before_host(
        self,
    ):
        invalid = [
            {**invoke_request(), "authority_ref": "caller-authority"},
            {**invoke_request(), "session_isolation": "host_isolated"},
            {**invoke_request(), "host_isolation": True},
            {
                key: value
                for key, value in invoke_request().items()
                if key != "interaction_mode"
            },
            {**invoke_request(), "interaction_mode": "host_isolated"},
            {**invoke_request(), "interaction_mode": "unknown"},
            {
                **invoke_request(),
                "action": {
                    "kind": "click",
                    "button": "left",
                    "count": 1,
                    "allow_coordinate_fallback": False,
                },
            },
            {
                **invoke_request(),
                "action": {
                    "kind": "type_text",
                    "text": "secret",
                    "clear": False,
                    "press_return": False,
                },
            },
            {
                **invoke_request(),
                "action": {"kind": "press", "key": "Enter", "count": 1},
            },
            {**invoke_request(), "action": {"kind": "paste", "text": "secret"}},
            {**invoke_request(), "action": {"kind": "hotkey", "keys": ["Meta", "A"]}},
            {
                **invoke_request(),
                "action": {"kind": "scroll", "direction": "down", "amount": 1},
            },
            {**invoke_request(), "action": {"kind": "move"}},
            {
                **invoke_request(),
                "verification": {"kind": "target_value_hash", "sha256": "a" * 64},
            },
            {
                **set_value_request(),
                "verification": {"kind": "target_value_hash", "sha256": "a" * 64},
            },
            {**invoke_request(), "deadline_at_ms": 9007199254740992},
            set_value_request("é" * 8193),
            {**set_value_request(), "action": {"kind": "set_value", "value": "\ud800"}},
        ]
        with patch.object(plugin, "_run_host_executor") as run:
            for value in invalid:
                self.assertEqual(
                    json.loads(plugin._execute(value)),
                    {"error": {"code": "invalid_request"}, "retry_safe": False},
                )
        run.assert_not_called()

    def test_host_executor_errors_do_not_escape(self):
        with patch.object(
            plugin, "_run_host_executor", side_effect=RuntimeError("backend secret")
        ):
            result = json.loads(plugin._execute(invoke_request()))
        self.assertNotIn("backend secret", json.dumps(result))

    def test_host_executor_receives_a_single_json_request(self):
        with (
            patch.dict(
                os.environ,
                {"PRAEFECTUS_HOST_EXECUTOR": "/host/praefectus-bridge"},
                clear=True,
            ),
            patch.object(plugin, "_invoke", return_value=(0, {"ok": True})) as invoke,
        ):
            self.assertEqual(
                plugin._run_host_executor({"operation_id": "op-1"}), {"ok": True}
            )
        self.assertEqual(
            invoke.call_args.args,
            (
                ["/host/praefectus-bridge"],
                {"operation": "execute", "request": {"operation_id": "op-1"}},
                "host executor failed",
            ),
        )

    def test_subprocess_output_is_bounded(self):
        with self.assertRaisesRegex(RuntimeError, "host executor failed"):
            plugin._invoke(
                [sys.executable, "-c", 'import sys;sys.stdout.write("x" * 1048577)'],
                None,
                "host executor failed",
            )

    @unittest.skipUnless(os.name == "posix", "requires POSIX process groups")
    def test_subprocess_descendant_cannot_hold_pipes_open(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory, "descendant")
            code = (
                "import os,pathlib,time\n"
                "marker=pathlib.Path(os.environ['PRAEFECTUS_TEST_MARKER'])\n"
                "pid=os.fork()\n"
                "if pid==0:\n"
                " marker.write_text(str(os.getpid()))\n"
                " time.sleep(60)\n"
                " os._exit(0)\n"
                "while not marker.exists():\n"
                " time.sleep(0.001)\n"
                "os._exit(0)\n"
            )
            started = time.monotonic()
            with (
                patch.dict(
                    os.environ, {"PRAEFECTUS_TEST_MARKER": str(marker)}, clear=False
                ),
                self.assertRaisesRegex(RuntimeError, "host executor failed"),
            ):
                plugin._invoke(
                    [sys.executable, "-c", code],
                    {"value": "x" * 900000},
                    "host executor failed",
                )
            self.assertLess(time.monotonic() - started, 2)
            self.assertTrue(marker.exists())
            descendant = int(marker.read_text())
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    os.kill(descendant, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.01)
            else:
                self.fail("descendant remained alive")

    def test_cli_envelopes_are_unchanged_at_boundaries_and_redacted(self):
        redacted = plugin._redact({"ok": True, "data": outcome_unknown()}, "op-1")
        terminal = redacted["data"]["acknowledgements"][0]["terminal"]
        self.assertFalse(terminal["retry_safe"])
        self.assertNotIn("backend secret", json.dumps(redacted))

    def test_receipt_exposes_validated_delivery_and_context_facts(self):
        redacted = plugin._redact(
            outcome_unknown(
                interaction_mode="background_only",
                context_preservation="unchanged_at_boundaries",
            ),
            "op-1",
        )
        receipt = redacted["acknowledgements"][0]["terminal"]["receipt"]
        self.assertEqual(
            {
                key: receipt[key]
                for key in (
                    "delivery_route",
                    "session_isolation",
                    "interaction_mode",
                    "context_preservation",
                )
            },
            {
                "delivery_route": "target_addressed",
                "session_isolation": "shared_desktop",
                "interaction_mode": "background_only",
                "context_preservation": "unchanged_at_boundaries",
            },
        )

    def test_preserves_valid_outcome_unknown_effects_as_nonretryable(self):
        for request, effect in (
            (invoke_request(), "executed_unverified"),
            (set_value_request(), "executed_unverified"),
            (set_value_request(), "verified"),
        ):
            result = outcome_unknown()
            terminal = result["acknowledgements"][0]["state"]["terminal"]
            terminal["receipt"]["action_name"] = request["action"]["kind"]
            terminal["receipt"]["effect"] = effect
            with patch.object(plugin, "_run_host_executor", return_value=result):
                executed = json.loads(plugin._execute(request))
            with patch.object(plugin, "_run", return_value=(0, result)):
                status = json.loads(plugin._status({"operation_id": "op-1"}))
            for safe_result in (executed, status):
                self.assertNotIn("error", safe_result)
                safe_terminal = safe_result["acknowledgements"][0]["terminal"]
                self.assertFalse(safe_terminal["retry_safe"])
                self.assertEqual(safe_terminal["receipt"]["effect"], effect)

    def test_status_preserves_verified_invoke_when_terminal_durability_is_unknown(self):
        result = outcome_unknown()
        result["acknowledgements"][0]["state"]["terminal"]["receipt"]["effect"] = (
            "verified"
        )
        with patch.object(plugin, "_run", return_value=(0, result)):
            status = json.loads(plugin._status({"operation_id": "op-1"}))
        self.assertNotIn("error", status)
        terminal = status["acknowledgements"][0]["terminal"]
        self.assertFalse(terminal["retry_safe"])
        self.assertEqual(terminal["receipt"]["effect"], "verified")

    def test_receipt_rejects_invalid_delivery_and_context_facts(self):
        invalid = []
        for key, value in (
            ("delivery_route", "pointer"),
            ("session_isolation", "caller_selected"),
            ("interaction_mode", "host_isolated"),
            ("context_preservation", "claimed"),
        ):
            result = outcome_unknown()
            result["acknowledgements"][0]["state"]["terminal"]["receipt"][key] = value
            invalid.append(result)
        invalid.append(
            outcome_unknown(
                interaction_mode="interactive",
                context_preservation="unchanged_at_boundaries",
            )
        )
        invalid.append(
            outcome_unknown(
                interaction_mode="background_only",
                session_isolation="host_isolated",
                context_preservation="unchanged_at_boundaries",
            )
        )
        changed_effect = outcome_unknown(
            interaction_mode="background_only",
            context_preservation="changed",
        )
        changed_effect["acknowledgements"][0]["state"]["terminal"]["receipt"][
            "effect"
        ] = "executed_unverified"
        invalid.append(changed_effect)
        changed_success = outcome_unknown(
            interaction_mode="background_only",
            context_preservation="changed",
        )
        terminal = changed_success["acknowledgements"][0]["state"]["terminal"]
        terminal["kind"] = "succeeded"
        terminal["receipt"]["effect"] = "executed_unverified"
        del terminal["message"]
        invalid.append(changed_success)
        recovery_success = legacy_recovery()
        terminal = recovery_success["acknowledgements"][0]["state"]["terminal"]
        terminal["kind"] = "succeeded"
        terminal["receipt"]["effect"] = "executed_unverified"
        del terminal["message"]
        invalid.append(recovery_success)
        unverified_set_value_success = outcome_unknown()
        terminal = unverified_set_value_success["acknowledgements"][0]["state"][
            "terminal"
        ]
        terminal["kind"] = "succeeded"
        terminal["receipt"]["action_name"] = "set_value"
        terminal["receipt"]["effect"] = "executed_unverified"
        del terminal["message"]
        invalid.append(unverified_set_value_success)
        for result in invalid:
            self.assertEqual(
                plugin._redact(result, "op-1"),
                {"error": {"code": "praefectus_error"}},
            )

    def test_legacy_recovery_unknown_facts_remain_nonretryable(self):
        recovery = legacy_recovery()
        with patch.object(plugin, "_run_host_executor", return_value=recovery):
            executed = json.loads(plugin._execute(invoke_request()))
        with patch.object(plugin, "_run", return_value=(0, recovery)):
            status = json.loads(plugin._status({"operation_id": "op-1"}))
        for result in (executed, status):
            self.assertNotIn("error", result)
            terminal = result["acknowledgements"][0]["terminal"]
            self.assertFalse(terminal["retry_safe"])
            receipt = terminal["receipt"]
            self.assertEqual(receipt["delivery_route"], "unknown")
            self.assertEqual(receipt["session_isolation"], "unknown")
            self.assertEqual(receipt["interaction_mode"], "unknown")
            self.assertEqual(receipt["context_preservation"], "unavailable")

    def test_capabilities_advertise_only_stable_semantic_effects(self):
        runtime = runtime_capabilities()
        result = plugin._redact(runtime)
        self.assertEqual(
            result,
            {
                **runtime,
                "supported_actions": ["invoke", "set_value"],
                "action_capabilities": [
                    runtime["action_capabilities"][0],
                    runtime["action_capabilities"][2],
                ],
            },
        )

    def test_capabilities_reject_mismatched_background_facts(self):
        runtime = runtime_capabilities()
        for facts in (
            [],
            [{**runtime["action_capabilities"][0], "delivery_route": "pointer"}],
        ):
            self.assertEqual(
                plugin._redact({**runtime, "action_capabilities": facts}),
                {"error": {"code": "praefectus_error"}},
            )

    def test_capabilities_reject_malicious_metadata(self):
        runtime = runtime_capabilities()
        missing_backend = dict(runtime)
        del missing_backend["backend"]
        malicious = [
            {**runtime, "platform": "secret-platform"},
            {**runtime, "backend": "credential-backend"},
            {**runtime, "display_geometry_hash": "A" * 64},
            {
                **runtime,
                "permissions": {**runtime["permissions"], "token_secret": True},
            },
            {**runtime, "detail": "backend secret"},
            {
                **runtime,
                "supported_actions": [*runtime["supported_actions"], "invoke"],
            },
            {
                **runtime,
                "action_capabilities": [
                    *runtime["action_capabilities"],
                    runtime["action_capabilities"][0],
                ],
            },
            {
                **runtime,
                "supported_actions": ["credential_backend"],
                "action_capabilities": [
                    {
                        "action": "credential_backend",
                        "delivery_route": "target_addressed",
                        "background_support": "guarded",
                    }
                ],
            },
            {**runtime, "permissions": {**runtime["permissions"], "accessibility": 1}},
            missing_backend,
        ]
        linux = runtime_capabilities("linux")
        del linux["permissions"]["x11"]
        malicious.append(linux)
        browser = runtime_capabilities("browser")
        browser["action_capabilities"][0]["background_support"] = "guarded"
        malicious.append(browser)
        for value in malicious:
            redacted = plugin._redact(value)
            self.assertEqual(redacted, {"error": {"code": "praefectus_error"}})
            self.assertNotIn("secret", json.dumps(redacted))
            self.assertNotIn("credential", json.dumps(redacted))

    def test_capabilities_accept_exact_full_runtime_contracts(self):
        for platform in ("macos", "windows", "linux", "browser"):
            runtime = runtime_capabilities(platform)
            redacted = plugin._redact(runtime)
            self.assertNotIn("error", redacted)
            self.assertEqual(redacted["platform"], platform)
            self.assertEqual(
                redacted["supported_actions"],
                [
                    action
                    for action in runtime["supported_actions"]
                    if action in ("invoke", "set_value")
                ],
            )

    def test_cli_errors_do_not_escape_backend_details(self):
        with patch.object(plugin, "_run", side_effect=RuntimeError("backend secret")):
            status = json.loads(plugin._status({"operation_id": "op-1"}))
            capabilities = json.loads(plugin._capabilities({}))
        self.assertEqual(status["error"], "Praefectus status is unavailable")
        self.assertEqual(
            capabilities["error"], "Praefectus capabilities are unavailable"
        )

    def test_malformed_error_codes_are_redacted(self):
        result = plugin._redact(
            {
                "ok": False,
                "error": {"code": "backend secret", "message": "credential"},
                "retry_safe": False,
            }
        )
        self.assertEqual(
            result,
            {"ok": False, "error": {"code": "praefectus_error"}, "retry_safe": False},
        )

    def test_malformed_child_protocol_is_rejected_without_details(self):
        malformed = [
            "backend secret",
            {"acknowledgements": [{"state": "backend secret"}]},
            {
                "acknowledgements": [
                    {"state": {"kind": "terminal", "terminal": "backend secret"}}
                ]
            },
            {
                "acknowledgements": [
                    {
                        "state": {
                            "kind": "terminal",
                            "terminal": {
                                "kind": "outcome_unknown",
                                "receipt": "backend secret",
                            },
                        }
                    }
                ]
            },
            {
                "stderr": "token=secret",
                "path": "/Users/private",
                "detail": "credential",
                "name": "semantic secret",
                "element_id": "element secret",
                "observation_id": "observation secret",
            },
            {"ok": True, "data": {"stderr": "token=secret"}},
        ]
        for value in malformed:
            self.assertEqual(
                plugin._redact(value), {"error": {"code": "praefectus_error"}}
            )
        with patch.object(
            plugin, "_run_host_executor", return_value={"stderr": "token=secret"}
        ):
            self.assertEqual(
                json.loads(plugin._execute(invoke_request())),
                {"error": {"code": "praefectus_error"}, "retry_safe": False},
            )

    def test_execute_rejects_malformed_or_mismatched_acknowledgements(self):
        malformed = {
            "acknowledgements": [
                {
                    "state": {
                        "kind": "terminal",
                        "terminal": {"kind": "succeeded", "receipt": {}},
                    }
                }
            ]
        }
        accepted_only = {
            "acknowledgements": [
                {
                    "protocol_version": 2,
                    "operation_id": "op-1",
                    "sequence": 0,
                    "action_hash": ACTION_HASH,
                    "replayed": False,
                    "state": {"kind": "accepted"},
                }
            ]
        }
        mixed_hashes = outcome_unknown()
        mixed_hashes["acknowledgements"].insert(
            0,
            {
                "protocol_version": 2,
                "operation_id": "op-1",
                "sequence": 0,
                "action_hash": "b" * 64,
                "replayed": False,
                "state": {"kind": "accepted"},
            },
        )
        stale_acknowledgement = outcome_unknown()
        stale_acknowledgement["acknowledgements"][0]["protocol_version"] = 1
        stale_receipt = outcome_unknown()
        stale_receipt["acknowledgements"][0]["state"]["terminal"]["receipt"][
            "protocol_version"
        ] = 1
        for value in (
            malformed,
            outcome_unknown("another-operation"),
            accepted_only,
            mixed_hashes,
            stale_acknowledgement,
            stale_receipt,
        ):
            with patch.object(plugin, "_run_host_executor", return_value=value):
                self.assertEqual(
                    json.loads(plugin._execute(invoke_request())),
                    {"error": {"code": "praefectus_error"}, "retry_safe": False},
                )

    def test_execute_accepts_verified_set_value_with_target_value_hash(self):
        value = outcome_unknown()
        terminal = value["acknowledgements"][0]["state"]["terminal"]
        terminal["kind"] = "succeeded"
        terminal["receipt"]["action_name"] = "set_value"
        terminal["receipt"]["effect"] = "verified"
        del terminal["message"]
        with patch.object(plugin, "_run_host_executor", return_value=value):
            result = json.loads(plugin._execute(set_value_request()))
        self.assertNotIn("error", result)
        self.assertNotIn("secret", json.dumps(result))

    def test_execute_accepts_set_value_at_utf8_byte_limit(self):
        value = outcome_unknown()
        terminal = value["acknowledgements"][0]["state"]["terminal"]
        terminal["kind"] = "succeeded"
        terminal["receipt"]["action_name"] = "set_value"
        terminal["receipt"]["effect"] = "verified"
        del terminal["message"]
        request = set_value_request("é" * 8192)
        with patch.object(plugin, "_run_host_executor", return_value=value) as run:
            result = json.loads(plugin._execute(request))
        run.assert_called_once_with(request)
        self.assertNotIn("error", result)

    def test_target_value_hash_schema_is_strict(self):
        verification = plugin._VERIFICATION["oneOf"][1]
        self.assertEqual(verification["required"], ["kind", "sha256"])
        self.assertFalse(verification["additionalProperties"])
        self.assertEqual(
            verification["properties"]["kind"], {"const": "target_value_hash"}
        )
        self.assertEqual(
            verification["properties"]["sha256"],
            {
                "type": "string",
                "minLength": 64,
                "maxLength": 64,
                "pattern": "^[0-9a-f]{64}$",
            },
        )


if __name__ == "__main__":
    unittest.main()
