import importlib.util
import json
import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


registry = types.ModuleType("tools.registry")
registry.tool_error = lambda message: json.dumps({"error": message})
tools = types.ModuleType("tools")
tools.registry = registry
sys.modules.update({"tools": tools, "tools.registry": registry})
spec = importlib.util.spec_from_file_location("praefectus_hermes", Path(__file__).with_name("__init__.py"))
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)


class PluginTest(unittest.TestCase):
    def test_registration_uses_native_hermes_contract(self):
        registrations = []
        context = types.SimpleNamespace(register_tool=lambda **kwargs: registrations.append(kwargs))
        plugin.register(context)
        self.assertEqual([item["name"] for item in registrations], ["praefectus_execute", "praefectus_status", "praefectus_capabilities"])
        self.assertTrue(all(item["toolset"] == "praefectus" for item in registrations))
        self.assertFalse(plugin.EXECUTE_SCHEMA["parameters"]["additionalProperties"])
        self.assertNotIn("authority_ref", plugin.EXECUTE_SCHEMA["parameters"]["properties"])

    def test_execute_sends_only_the_action_request_to_host_executor(self):
        captured = []

        def run(request):
            captured.append(request)
            return {"acknowledgements": [{"protocol_version": 1, "operation_id": "op-1", "sequence": 3, "action_hash": "hash", "replayed": False, "state": {"kind": "terminal", "terminal": {"kind": "outcome_unknown", "message": "typed secret", "receipt": {"protocol_version": 1, "action_name": "type_text", "action_hash": "hash", "started_at_ms": 1, "finished_at_ms": 2, "backend": "test", "fallback_chain": [], "effect": "unknown", "before": {"secret": "x"}, "warnings": []}}}}]}

        args = {"operation_id": "op-1", "authority_ref": "attacker-ref", "signed_authority": "attacker-signature", "action": {"kind": "type_text", "text": "secret", "clear": False, "press_return": False, "delay_ms": None}, "target": {"kind": "none"}, "deadline_at_ms": 9, "verification": {"kind": "none"}, "safety": "external"}
        with patch.object(plugin, "_run_host_executor", run):
            result = json.loads(plugin._execute(args))
        self.assertEqual(captured[0]["operation_id"], "op-1")
        self.assertNotIn("protocol_version", captured[0])
        self.assertNotIn("authority_ref", captured[0])
        self.assertNotIn("signed_authority", captured[0])
        self.assertNotIn("secret", json.dumps(result))
        self.assertFalse(result["acknowledgements"][0]["terminal"]["retry_safe"])

    def test_execute_fails_closed_without_host_authority(self):
        with patch.dict(os.environ, {}, clear=True):
            result = json.loads(plugin._execute({}))
        self.assertEqual(result["error"], "Praefectus host executor is unavailable")

    def test_coordinate_targets_require_snapshot_content_hash(self):
        coordinate = plugin._TARGET["oneOf"][1]
        self.assertIn("snapshot_content_hash", coordinate["required"])

    def test_host_executor_errors_do_not_escape(self):
        with patch.object(plugin, "_run_host_executor", side_effect=RuntimeError("backend secret")):
            result = json.loads(plugin._execute({}))
        self.assertNotIn("backend secret", json.dumps(result))

    def test_host_executor_receives_a_single_json_request(self):
        completed = types.SimpleNamespace(returncode=0, stdout='{"ok":true}')
        with patch.dict(os.environ, {"PRAEFECTUS_HOST_EXECUTOR": "/host/praefectus-bridge"}, clear=True), patch.object(plugin.subprocess, "run", return_value=completed) as run:
            self.assertEqual(plugin._run_host_executor({"operation_id": "op-1"}), {"ok": True})
        self.assertEqual(run.call_args.args[0], ["/host/praefectus-bridge"])
        self.assertEqual(json.loads(run.call_args.kwargs["input"]), {"operation": "execute", "request": {"operation_id": "op-1"}})


if __name__ == "__main__":
    unittest.main()
