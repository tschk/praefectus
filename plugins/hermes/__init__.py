from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from tools.registry import tool_error

_MAX_IO_BYTES = 1024 * 1024


def _object(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


_ACTION = {
    "oneOf": [
        _object({"kind": {"const": "click"}, "button": {"enum": ["left", "right", "middle"]}, "count": {"type": "integer", "minimum": 1, "maximum": 3}, "allow_coordinate_fallback": {"type": "boolean"}}, ["kind", "button", "count", "allow_coordinate_fallback"]),
        _object({"kind": {"const": "type_text"}, "text": {"type": "string", "minLength": 1, "maxLength": 16384}, "clear": {"type": "boolean"}, "press_return": {"type": "boolean"}, "delay_ms": {"anyOf": [{"type": "integer", "minimum": 0, "maximum": 1000}, {"type": "null"}]}}, ["kind", "text", "clear", "press_return"]),
        _object({"kind": {"const": "press"}, "key": {"type": "string", "minLength": 1, "maxLength": 64}, "count": {"type": "integer", "minimum": 1, "maximum": 100}, "delay_ms": {"anyOf": [{"type": "integer", "minimum": 0, "maximum": 1000}, {"type": "null"}]}}, ["kind", "key", "count"]),
        _object({"kind": {"const": "paste"}, "text": {"type": "string", "minLength": 1, "maxLength": 16384}}, ["kind", "text"]),
        _object({"kind": {"const": "hotkey"}, "keys": {"type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 64}, "minItems": 1, "maxItems": 8}}, ["kind", "keys"]),
        _object({"kind": {"const": "scroll"}, "direction": {"enum": ["up", "down", "left", "right"]}, "amount": {"type": "integer", "minimum": 1, "maximum": 100}}, ["kind", "direction", "amount"]),
        _object({"kind": {"const": "move"}}, ["kind"]),
        _object({"kind": {"const": "set_value"}, "value": {"type": "string", "maxLength": 16384}}, ["kind", "value"]),
    ]
}

_HASH = {"type": "string", "minLength": 64, "maxLength": 64, "pattern": "^[0-9A-Fa-f]+$"}
_SNAPSHOT_ID = {"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[^\\x00-\\x1F\\x7F-\\x9F]+$"}
_IDENTIFIER = {"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[A-Za-z0-9_:-]+$"}
_RECT = _object({"x": {"type": "integer"}, "y": {"type": "integer"}, "width": {"type": "integer", "minimum": 1}, "height": {"type": "integer", "minimum": 1}}, ["x", "y", "width", "height"])
_FINGERPRINT = _object(
    {
        "backend": {"type": "string", "minLength": 1},
        "id": {"type": "string", "minLength": 1},
        "app": {"type": "string", "minLength": 1},
        "process_id": {"type": "integer", "minimum": 1},
        "window": {"type": "string", "minLength": 1},
        "role": {"type": "string", "minLength": 1},
        "label": {"type": "string"},
        "bounds": _RECT,
    },
    ["backend", "id", "app", "process_id", "window", "role", "label", "bounds"],
)
_TARGET = {
    "oneOf": [
        _object({"kind": {"const": "none"}}, ["kind"]),
        _object({"kind": {"const": "coordinates"}, "x": {"type": "integer"}, "y": {"type": "integer"}, "display_id": {"type": "string", "minLength": 1, "maxLength": 256}, "display_geometry_hash": _HASH, "snapshot_id": _SNAPSHOT_ID, "snapshot_content_hash": _HASH}, ["kind", "x", "y", "display_id", "display_geometry_hash", "snapshot_id", "snapshot_content_hash"]),
        _object({"kind": {"const": "element"}, "selector": {"type": "string", "minLength": 1, "maxLength": 1024}, "snapshot_id": _SNAPSHOT_ID, "element_fingerprint": _FINGERPRINT}, ["kind", "selector", "snapshot_id", "element_fingerprint"]),
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
            "operation_id": _IDENTIFIER,
            "action": _ACTION,
            "target": _TARGET,
            "deadline_at_ms": {"type": "integer", "minimum": 1},
            "verification": _VERIFICATION,
            "safety": {"enum": ["reversible", "external", "destructive"]},
        },
        ["operation_id", "action", "target", "deadline_at_ms", "verification", "safety"],
    ),
}

STATUS_SCHEMA = {
    "name": "praefectus_status",
    "description": "Read the durable terminal state of a Praefectus operation.",
    "parameters": _object({"operation_id": _IDENTIFIER}, ["operation_id"]),
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


def _invoke(command: list[str], payload: dict[str, Any] | None, error_message: str) -> tuple[int, dict[str, Any]]:
    input_bytes = None if payload is None else json.dumps(payload).encode()
    if input_bytes is not None and len(input_bytes) > _MAX_IO_BYTES:
        raise RuntimeError(error_message)
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL if input_bytes is None else subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError as error:
        raise RuntimeError(error_message) from error

    def write_input() -> None:
        if input_bytes is None or process.stdin is None:
            return
        try:
            process.stdin.write(input_bytes)
            process.stdin.flush()
        except BrokenPipeError:
            pass
        finally:
            process.stdin.close()

    def read_output() -> bytes:
        if process.stdout is None:
            raise RuntimeError(error_message)
        output = bytearray()
        while chunk := process.stdout.read(65536):
            output.extend(chunk)
            if len(output) > _MAX_IO_BYTES:
                process.kill()
                raise RuntimeError(error_message)
        return bytes(output)

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            writer = executor.submit(write_input)
            reader = executor.submit(read_output)
            try:
                returncode = process.wait(timeout=30)
            except subprocess.TimeoutExpired as error:
                process.kill()
                process.wait()
                raise RuntimeError(error_message) from error
            try:
                writer.result()
                output = reader.result()
            except (OSError, RuntimeError) as error:
                raise RuntimeError(error_message) from error
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()
        if process.stdout is not None:
            process.stdout.close()
    try:
        result = json.loads(output.decode())
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(error_message) from error
    if not isinstance(result, dict):
        raise RuntimeError(error_message)
    return returncode, result


def _run(arguments: list[str], payload: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    return _invoke([_binary(), *arguments], payload, "praefectus command failed")


def _run_host_executor(request: dict[str, Any]) -> dict[str, Any]:
    bridge = os.environ.get("PRAEFECTUS_HOST_EXECUTOR")
    if not bridge:
        raise RuntimeError("host executor is not configured")
    returncode, result = _invoke([bridge], {"operation": "execute", "request": request}, "host executor failed")
    if returncode != 0:
        raise RuntimeError("host executor failed")
    return result


def _receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        key: receipt[key]
        for key in ("protocol_version", "action_name", "action_hash", "started_at_ms", "finished_at_ms", "backend", "effect")
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
    if result.get("ok") is True:
        data = result.get("data")
        return {"ok": True, "data": _redact(data) if isinstance(data, dict) else None}
    if result.get("ok") is False:
        error = result.get("error")
        code = error.get("code") if isinstance(error, dict) else None
        redacted = {"ok": False, "error": {"code": code if isinstance(code, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code) else "praefectus_error"}}
        if result.get("retry_safe") is False:
            redacted["retry_safe"] = False
        return redacted
    if isinstance(result.get("acknowledgements"), list):
        return {"acknowledgements": [_ack(item) for item in result["acknowledgements"] if isinstance(item, dict)]}
    if isinstance(result.get("state"), dict):
        return _ack(result)
    if isinstance(result.get("error"), dict):
        code = result["error"].get("code")
        redacted = {"error": {"code": code if isinstance(code, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code) else "praefectus_error"}}
        if result.get("retry_safe") is False:
            redacted["retry_safe"] = False
        return redacted
    return {key: result[key] for key in ("platform", "backend", "supported_actions", "permissions", "display_geometry_hash") if key in result}


def _execute(args: dict[str, Any], **_: Any) -> str:
    request = {
        key: args[key]
        for key in ("operation_id", "action", "target", "deadline_at_ms", "verification", "safety")
        if key in args
    }
    try:
        return json.dumps(_redact(_run_host_executor(request)))
    except (TypeError, ValueError, RuntimeError):
        return json.dumps({"error": {"code": "host_executor_unavailable"}, "retry_safe": False})


def _status(args: dict[str, Any], **_: Any) -> str:
    try:
        _, result = _run(["status", args["operation_id"]])
        return json.dumps(_redact(result))
    except (KeyError, TypeError, ValueError, RuntimeError):
        return tool_error("Praefectus status is unavailable")


def _capabilities(args: dict[str, Any], **_: Any) -> str:
    try:
        _, result = _run(["capabilities"])
        return json.dumps(_redact(result))
    except (TypeError, ValueError, RuntimeError):
        return tool_error("Praefectus capabilities are unavailable")


def register(ctx: Any) -> None:
    for name, schema, handler in (
        ("praefectus_execute", EXECUTE_SCHEMA, _execute),
        ("praefectus_status", STATUS_SCHEMA, _status),
        ("praefectus_capabilities", CAPABILITIES_SCHEMA, _capabilities),
    ):
        ctx.register_tool(name=name, toolset="praefectus", schema=schema, handler=handler, check_fn=_available)
