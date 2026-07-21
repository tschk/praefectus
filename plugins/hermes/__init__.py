from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from tools.registry import tool_error


def _object(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


_ACTION = {
    "oneOf": [
        _object({"kind": {"const": "click"}, "button": {"enum": ["left", "right", "middle"]}, "count": {"type": "integer", "minimum": 1}, "allow_coordinate_fallback": {"type": "boolean"}}, ["kind", "button", "count", "allow_coordinate_fallback"]),
        _object({"kind": {"const": "type_text"}, "text": {"type": "string"}, "clear": {"type": "boolean"}, "press_return": {"type": "boolean"}, "delay_ms": {"type": ["integer", "null"], "minimum": 0}}, ["kind", "text", "clear", "press_return", "delay_ms"]),
        _object({"kind": {"const": "press"}, "key": {"type": "string", "minLength": 1}, "count": {"type": "integer", "minimum": 1}, "delay_ms": {"type": ["integer", "null"], "minimum": 0}}, ["kind", "key", "count", "delay_ms"]),
        _object({"kind": {"const": "paste"}, "text": {"type": "string"}}, ["kind", "text"]),
        _object({"kind": {"const": "hotkey"}, "keys": {"type": "array", "items": {"type": "string", "minLength": 1}, "minItems": 1}}, ["kind", "keys"]),
        _object({"kind": {"const": "scroll"}, "direction": {"enum": ["up", "down", "left", "right"]}, "amount": {"type": "integer", "minimum": 1}}, ["kind", "direction", "amount"]),
        _object({"kind": {"const": "move"}}, ["kind"]),
        _object({"kind": {"const": "set_value"}, "value": {"type": "string"}}, ["kind", "value"]),
    ]
}

_RECT = _object({name: {"type": "integer"} for name in ("x", "y", "width", "height")}, ["x", "y", "width", "height"])
_FINGERPRINT = _object(
    {
        "backend": {"type": "string", "minLength": 1},
        "id": {"type": "string", "minLength": 1},
        "app": {"type": "string"},
        "process_id": {"type": "integer", "minimum": 0},
        "window": {"type": "string", "minLength": 1},
        "role": {"type": "string"},
        "label": {"type": "string"},
        "bounds": {"anyOf": [_RECT, {"type": "null"}]},
    },
    ["backend", "id", "app", "process_id", "window", "role", "label", "bounds"],
)
_TARGET = {
    "oneOf": [
        _object({"kind": {"const": "none"}}, ["kind"]),
        _object({"kind": {"const": "coordinates"}, "x": {"type": "integer"}, "y": {"type": "integer"}, "display_id": {"type": "string", "minLength": 1}, "display_geometry_hash": {"type": "string", "minLength": 1}, "snapshot_id": {"type": "string", "minLength": 1}, "snapshot_content_hash": {"type": "string", "minLength": 1}}, ["kind", "x", "y", "display_id", "display_geometry_hash", "snapshot_id", "snapshot_content_hash"]),
        _object({"kind": {"const": "element"}, "selector": {"type": "string", "minLength": 1}, "snapshot_id": {"type": "string", "minLength": 1}, "element_fingerprint": _FINGERPRINT}, ["kind", "selector", "snapshot_id", "element_fingerprint"]),
    ]
}
_VERIFICATION = {
    "oneOf": [
        _object({"kind": {"enum": ["none", "snapshot_changed"]}}, ["kind"]),
        _object({"kind": {"const": "target_state"}, "expected": {}}, ["kind", "expected"]),
    ]
}

EXECUTE_SCHEMA = {
    "name": "praefectus_execute",
    "description": "Execute one approved desktop action. The host supplies and verifies authority; outcome_unknown must never be retried automatically.",
    "parameters": _object(
        {
            "operation_id": {"type": "string", "minLength": 1},
            "action": _ACTION,
            "target": _TARGET,
            "deadline_at_ms": {"type": "integer"},
            "verification": _VERIFICATION,
            "safety": {"enum": ["reversible", "external", "destructive"]},
        },
        ["operation_id", "action", "target", "deadline_at_ms", "verification", "safety"],
    ),
}

STATUS_SCHEMA = {
    "name": "praefectus_status",
    "description": "Read the durable terminal state of a Praefectus operation.",
    "parameters": _object({"operation_id": {"type": "string", "minLength": 1}}, ["operation_id"]),
}

CAPABILITIES_SCHEMA = {
    "name": "praefectus_capabilities",
    "description": "Read available desktop actions, backend, and permissions.",
    "parameters": _object({}, []),
}


def _binary() -> str:
    return os.environ.get("PRAEFECTUS_BIN", "praefectus")


def _available() -> bool:
    binary = _binary()
    return Path(binary).is_file() or shutil.which(binary) is not None


def _run(arguments: list[str], payload: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    try:
        completed = subprocess.run(
            [_binary(), *arguments],
            input=None if payload is None else json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(str(error)) from error
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("praefectus returned invalid JSON") from error
    if not isinstance(result, dict):
        raise RuntimeError("praefectus returned a non-object result")
    return completed.returncode, result


def _run_host_executor(request: dict[str, Any]) -> dict[str, Any]:
    bridge = os.environ.get("PRAEFECTUS_HOST_EXECUTOR")
    if not bridge:
        raise RuntimeError("host executor is not configured")
    try:
        completed = subprocess.run(
            [bridge],
            input=json.dumps({"operation": "execute", "request": request}),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("host executor failed") from error
    if completed.returncode != 0:
        raise RuntimeError("host executor failed")
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("host executor returned invalid JSON") from error
    if not isinstance(result, dict):
        raise RuntimeError("host executor returned a non-object result")
    return result


def _receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        key: receipt[key]
        for key in ("protocol_version", "action_name", "action_hash", "started_at_ms", "finished_at_ms", "backend", "fallback_chain", "effect")
        if key in receipt
    }


def _ack(acknowledgement: dict[str, Any]) -> dict[str, Any]:
    result = {key: acknowledgement[key] for key in ("protocol_version", "operation_id", "sequence", "action_hash", "replayed") if key in acknowledgement}
    state = acknowledgement.get("state", {})
    kind = state.get("kind")
    result["state"] = kind
    if kind == "terminal":
        terminal = state.get("terminal", {})
        terminal_result = {"kind": terminal.get("kind")}
        if "code" in terminal:
            terminal_result["code"] = terminal["code"]
        if isinstance(terminal.get("receipt"), dict):
            terminal_result["receipt"] = _receipt(terminal["receipt"])
        if terminal.get("kind") == "outcome_unknown":
            terminal_result["retry_safe"] = False
        result["terminal"] = terminal_result
    return result


def _redact(result: dict[str, Any]) -> dict[str, Any]:
    if isinstance(result.get("acknowledgements"), list):
        return {"acknowledgements": [_ack(item) for item in result["acknowledgements"] if isinstance(item, dict)]}
    if isinstance(result.get("state"), dict):
        return _ack(result)
    if isinstance(result.get("error"), dict):
        return {"error": {"code": result["error"].get("code", "praefectus_error")}}
    return {key: result[key] for key in ("platform", "backend", "supported_actions", "permissions", "display_geometry_hash") if key in result}


def _execute(args: dict[str, Any], **_: Any) -> str:
    request = {
        key: args[key]
        for key in ("operation_id", "action", "target", "deadline_at_ms", "verification", "safety")
        if key in args
    }
    try:
        return json.dumps(_redact(_run_host_executor(request)))
    except (TypeError, ValueError, RuntimeError) as error:
        return tool_error("Praefectus host executor is unavailable")


def _status(args: dict[str, Any], **_: Any) -> str:
    try:
        _, result = _run(["status", args["operation_id"]])
        return json.dumps(_redact(result))
    except (KeyError, TypeError, ValueError, RuntimeError) as error:
        return tool_error(str(error))


def _capabilities(args: dict[str, Any], **_: Any) -> str:
    try:
        _, result = _run(["capabilities"])
        return json.dumps(_redact(result))
    except (TypeError, ValueError, RuntimeError) as error:
        return tool_error(str(error))


def register(ctx: Any) -> None:
    for name, schema, handler in (
        ("praefectus_execute", EXECUTE_SCHEMA, _execute),
        ("praefectus_status", STATUS_SCHEMA, _status),
        ("praefectus_capabilities", CAPABILITIES_SCHEMA, _capabilities),
    ):
        ctx.register_tool(name=name, toolset="praefectus", schema=schema, handler=handler, check_fn=_available)
