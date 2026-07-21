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

_SNAPSHOT_ID = {"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[^\\x00-\\x1F\\x7F-\\x9F]+$"}
_IDENTIFIER = {"type": "string", "minLength": 1, "maxLength": 256, "pattern": "^[A-Za-z0-9_:-]+$"}
_RECT = _object({"x": {"type": "integer"}, "y": {"type": "integer"}, "width": {"type": "integer", "minimum": 1}, "height": {"type": "integer", "minimum": 1}}, ["x", "y", "width", "height"])
_FINGERPRINT = _object(
    {
        "backend": {"type": "string", "minLength": 1, "maxLength": 128},
        "id": {"type": "string", "minLength": 1, "maxLength": 512},
        "app": {"type": "string", "minLength": 1, "maxLength": 256},
        "process_id": {"type": "integer", "minimum": 1},
        "window": {"type": "string", "minLength": 1, "maxLength": 512},
        "role": {"type": "string", "minLength": 1, "maxLength": 128},
        "label": {"type": "string", "maxLength": 1024},
        "bounds": _RECT,
    },
    ["backend", "id", "app", "process_id", "window", "role", "label", "bounds"],
)
_TARGET = _object({"kind": {"const": "element"}, "selector": {"type": "string", "minLength": 1, "maxLength": 1024}, "snapshot_id": _SNAPSHOT_ID, "element_fingerprint": _FINGERPRINT}, ["kind", "selector", "snapshot_id", "element_fingerprint"])
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
            "verification_version": {"const": 1},
            "safety": {"enum": ["reversible", "external", "destructive"]},
        },
        ["operation_id", "action", "target", "deadline_at_ms", "verification", "verification_version", "safety"],
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


def _only(value: dict[str, Any], keys: tuple[str, ...]) -> bool:
    return all(key in keys for key in value)


def _receipt(receipt: Any) -> dict[str, Any] | None:
    if (
        not isinstance(receipt, dict)
        or not _only(receipt, ("protocol_version", "action_name", "action_hash", "started_at_ms", "finished_at_ms", "backend", "fallback_chain", "effect", "before", "after", "warnings"))
        or receipt.get("protocol_version") != 1
        or receipt.get("action_name") not in ("click", "type_text", "press", "paste", "hotkey", "scroll", "move", "set_value")
        or not isinstance(receipt.get("action_hash"), str)
        or re.fullmatch(r"[0-9a-fA-F]{64}", receipt["action_hash"]) is None
        or not isinstance(receipt.get("started_at_ms"), int)
        or isinstance(receipt.get("started_at_ms"), bool)
        or receipt["started_at_ms"] < 0
        or not isinstance(receipt.get("finished_at_ms"), int)
        or isinstance(receipt.get("finished_at_ms"), bool)
        or receipt["finished_at_ms"] < receipt["started_at_ms"]
        or not isinstance(receipt.get("backend"), str)
        or re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", receipt["backend"]) is None
        or not isinstance(receipt.get("fallback_chain"), list)
        or not all(isinstance(item, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", item) for item in receipt["fallback_chain"])
        or receipt.get("effect") not in ("verified", "executed_unverified", "unknown")
        or "before" not in receipt
        or (receipt["before"] is not None and not isinstance(receipt["before"], dict))
        or "after" not in receipt
        or (receipt["after"] is not None and not isinstance(receipt["after"], dict))
        or not isinstance(receipt.get("warnings"), list)
        or not all(isinstance(item, str) for item in receipt["warnings"])
    ):
        return None
    return {key: receipt[key] for key in ("protocol_version", "action_name", "action_hash", "started_at_ms", "finished_at_ms", "backend", "effect")}


def _ack(acknowledgement: Any, expected_operation_id: str | None = None) -> dict[str, Any] | None:
    if (
        not isinstance(acknowledgement, dict)
        or not _only(acknowledgement, ("protocol_version", "operation_id", "sequence", "action_hash", "replayed", "state"))
        or acknowledgement.get("protocol_version") != 1
        or not isinstance(acknowledgement.get("operation_id"), str)
        or re.fullmatch(r"[A-Za-z0-9_:-]{1,256}", acknowledgement["operation_id"]) is None
        or (expected_operation_id is not None and acknowledgement["operation_id"] != expected_operation_id)
        or not isinstance(acknowledgement.get("sequence"), int)
        or isinstance(acknowledgement.get("sequence"), bool)
        or not 0 <= acknowledgement["sequence"] <= 2
        or not isinstance(acknowledgement.get("action_hash"), str)
        or re.fullmatch(r"[0-9a-fA-F]{64}", acknowledgement["action_hash"]) is None
        or not isinstance(acknowledgement.get("replayed"), bool)
    ):
        return None
    result = {key: acknowledgement[key] for key in ("protocol_version", "operation_id", "sequence", "action_hash", "replayed")}
    state = acknowledgement.get("state", {})
    if not isinstance(state, dict):
        return None
    kind = state.get("kind")
    if kind not in ("accepted", "executing", "terminal"):
        return None
    if (kind == "accepted" and acknowledgement["sequence"] != 0) or (kind == "executing" and acknowledgement["sequence"] != 1) or (kind == "terminal" and acknowledgement["sequence"] != 2):
        return None
    result["state"] = kind
    if kind != "terminal":
        return result if _only(state, ("kind",)) else None
    if not _only(state, ("kind", "terminal")):
        return None
    if kind == "terminal":
        terminal = state.get("terminal", {})
        if not isinstance(terminal, dict) or terminal.get("kind") not in ("succeeded", "rejected", "failed", "cancelled_before_effect", "expired_before_effect", "outcome_unknown"):
            return None
        terminal_keys = {
            "succeeded": ("kind", "receipt"),
            "rejected": ("kind", "code", "message"),
            "failed": ("kind", "code", "message"),
            "cancelled_before_effect": ("kind",),
            "expired_before_effect": ("kind",),
            "outcome_unknown": ("kind", "receipt", "message"),
        }[terminal["kind"]]
        if not _only(terminal, terminal_keys):
            return None
        terminal_result = {"kind": terminal.get("kind")}
        if "code" in terminal and terminal.get("code") not in ("invalid_request", "conflict", "stale_target", "target_not_found", "permission_denied", "unsupported", "dispatch_failed", "verification_failed"):
            return None
        if "code" in terminal:
            terminal_result["code"] = terminal["code"]
        if "receipt" in terminal:
            receipt = _receipt(terminal["receipt"])
            if receipt is None:
                return None
            if (terminal["kind"] == "succeeded" and receipt["effect"] == "unknown") or (terminal["kind"] == "outcome_unknown" and receipt["effect"] == "verified"):
                return None
            terminal_result["receipt"] = receipt
        if terminal.get("kind") in ("succeeded", "outcome_unknown") and "receipt" not in terminal_result:
            return None
        if terminal.get("kind") in ("rejected", "failed") and "code" not in terminal_result:
            return None
        if terminal.get("kind") in ("rejected", "failed", "outcome_unknown") and (not isinstance(terminal.get("message"), str) or len(terminal["message"]) > 1024):
            return None
        if terminal.get("kind") == "outcome_unknown":
            terminal_result["retry_safe"] = False
        result["terminal"] = terminal_result
    return result


def _redact(result: Any, expected_operation_id: str | None = None) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {"error": {"code": "praefectus_error"}}
    if result.get("ok") is True:
        data = result.get("data")
        if data is None:
            return {"ok": True, "data": None}
        if not isinstance(data, dict):
            return {"error": {"code": "praefectus_error"}}
        redacted = _redact(data, expected_operation_id)
        return redacted if "error" in redacted else {"ok": True, "data": redacted}
    if result.get("ok") is False:
        error = result.get("error")
        code = error.get("code") if isinstance(error, dict) else None
        redacted = {"ok": False, "error": {"code": code if isinstance(code, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code) else "praefectus_error"}}
        if result.get("retry_safe") is False:
            redacted["retry_safe"] = False
        return redacted
    if isinstance(result.get("acknowledgements"), list):
        acknowledgements = [_ack(item, expected_operation_id) for item in result["acknowledgements"]]
        return {"acknowledgements": acknowledgements} if acknowledgements and all(item is not None for item in acknowledgements) else {"error": {"code": "praefectus_error"}}
    if isinstance(result.get("state"), dict):
        return _ack(result, expected_operation_id) or {"error": {"code": "praefectus_error"}}
    if isinstance(result.get("error"), dict):
        code = result["error"].get("code")
        redacted = {"error": {"code": code if isinstance(code, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code) else "praefectus_error"}}
        if result.get("retry_safe") is False:
            redacted["retry_safe"] = False
        return redacted
    capabilities = {}
    for key in ("platform", "backend", "display_geometry_hash"):
        if isinstance(result.get(key), str):
            capabilities[key] = result[key]
    if isinstance(result.get("supported_actions"), list) and all(isinstance(action, str) for action in result["supported_actions"]):
        capabilities["supported_actions"] = result["supported_actions"]
    if isinstance(result.get("permissions"), dict) and all(isinstance(allowed, bool) for allowed in result["permissions"].values()):
        capabilities["permissions"] = result["permissions"]
    return capabilities or {"error": {"code": "praefectus_error"}}


def _valid_execution(result: dict[str, Any], request: dict[str, Any]) -> bool:
    data = result.get("data") if result.get("ok") is True else result
    action = request.get("action")
    verification = request.get("verification")
    acknowledgements = data.get("acknowledgements") if isinstance(data, dict) else None
    if not isinstance(action, dict) or not isinstance(verification, dict) or not isinstance(acknowledgements, list) or not acknowledgements:
        return False
    action_hash = acknowledgements[0].get("action_hash") if isinstance(acknowledgements[0], dict) else None
    previous_sequence = -1
    for index, acknowledgement in enumerate(acknowledgements):
        if (
            not isinstance(acknowledgement, dict)
            or acknowledgement.get("action_hash") != action_hash
            or not isinstance(acknowledgement.get("sequence"), int)
            or isinstance(acknowledgement.get("sequence"), bool)
            or acknowledgement["sequence"] <= previous_sequence
            or (acknowledgement.get("state") == "terminal" and index != len(acknowledgements) - 1)
        ):
            return False
        previous_sequence = acknowledgement["sequence"]
    terminal = acknowledgements[-1].get("terminal")
    if acknowledgements[-1].get("state") != "terminal" or not isinstance(terminal, dict):
        return False
    receipt = terminal.get("receipt")
    if receipt is None:
        return True
    if not isinstance(receipt, dict) or receipt.get("action_hash") != action_hash or receipt.get("action_name") != action.get("kind"):
        return False
    if terminal.get("kind") != "succeeded":
        return True
    return (verification.get("kind") == "none" and receipt.get("effect") == "executed_unverified") or (verification.get("kind") == "target_state" and receipt.get("effect") == "verified")


def _execute(args: dict[str, Any], **_: Any) -> str:
    request = {
        key: args[key]
        for key in ("operation_id", "action", "target", "deadline_at_ms", "verification", "verification_version", "safety")
        if key in args
    }
    try:
        result = _redact(_run_host_executor(request), args.get("operation_id"))
        if "error" not in result and not _valid_execution(result, args):
            result = {"error": {"code": "praefectus_error"}}
        if "error" in result:
            result["retry_safe"] = False
        return json.dumps(result)
    except (TypeError, ValueError, RuntimeError):
        return json.dumps({"error": {"code": "host_executor_unavailable"}, "retry_safe": False})


def _status(args: dict[str, Any], **_: Any) -> str:
    try:
        _, result = _run(["status", args["operation_id"]])
        return json.dumps(_redact(result, args["operation_id"]))
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
