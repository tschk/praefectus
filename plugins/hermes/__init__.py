from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from tools.registry import tool_error

_MAX_IO_BYTES = 1024 * 1024
_MAX_SAFE_INTEGER = 9007199254740991
_MAX_VALUE_BYTES = 16384
_PROCESS_TIMEOUT_SECONDS = 30
_CLEANUP_GRACE_SECONDS = 1


def _object(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


_INVOKE_ACTION = _object({"kind": {"const": "invoke"}}, ["kind"])
_SET_VALUE_ACTION = _object(
    {"kind": {"const": "set_value"}, "value": {"type": "string", "maxLength": 16384}},
    ["kind", "value"],
)
_ACTION = {"oneOf": [_INVOKE_ACTION, _SET_VALUE_ACTION]}

_IDENTIFIER = {
    "type": "string",
    "minLength": 1,
    "maxLength": 256,
    "pattern": "^[A-Za-z0-9_:-]+$",
}
_HASH = {
    "type": "string",
    "minLength": 64,
    "maxLength": 64,
    "pattern": "^[0-9a-f]{64}$",
}
_SEMANTIC_TARGET = _object(
    {
        "observation_id": _HASH,
        "generation": {"type": "integer", "minimum": 1, "maximum": _MAX_SAFE_INTEGER},
        "provenance_hash": _HASH,
        "element_id": _HASH,
        "fingerprint_hash": _HASH,
    },
    [
        "observation_id",
        "generation",
        "provenance_hash",
        "element_id",
        "fingerprint_hash",
    ],
)
_TARGET = _object(
    {"kind": {"const": "element"}, "target": _SEMANTIC_TARGET}, ["kind", "target"]
)
_NO_VERIFICATION = _object({"kind": {"const": "none"}}, ["kind"])
_VALUE_VERIFICATION = _object(
    {"kind": {"const": "target_value_hash"}, "sha256": _HASH}, ["kind", "sha256"]
)
_VERIFICATION = {"oneOf": [_NO_VERIFICATION, _VALUE_VERIFICATION]}

_REQUEST = _object(
    {
        "operation_id": _IDENTIFIER,
        "action": _ACTION,
        "target": _TARGET,
        "interaction_mode": {"enum": ["interactive", "background_only"]},
        "deadline_at_ms": {
            "type": "integer",
            "minimum": 1,
            "maximum": _MAX_SAFE_INTEGER,
        },
        "verification": _VERIFICATION,
        "verification_version": {"const": 2},
        "safety": {"enum": ["reversible", "external", "destructive"]},
    },
    [
        "operation_id",
        "action",
        "target",
        "interaction_mode",
        "deadline_at_ms",
        "verification",
        "verification_version",
        "safety",
    ],
)
_REQUEST["oneOf"] = [
    {"properties": {"action": _INVOKE_ACTION, "verification": _NO_VERIFICATION}},
    {"properties": {"action": _SET_VALUE_ACTION, "verification": _VALUE_VERIFICATION}},
]

EXECUTE_SCHEMA = {
    "name": "praefectus_execute",
    "description": "Execute one approved desktop action. The host supplies and verifies authority; outcome_unknown must never be retried automatically.",
    "parameters": _REQUEST,
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


def _invoke(
    command: list[str], payload: dict[str, Any] | None, error_message: str
) -> tuple[int, dict[str, Any]]:
    input_bytes = None if payload is None else json.dumps(payload).encode()
    if input_bytes is not None and len(input_bytes) > _MAX_IO_BYTES:
        raise RuntimeError(error_message)
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL if input_bytes is None else subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
            start_new_session=os.name == "posix",
        )
    except OSError as error:
        raise RuntimeError(error_message) from error

    terminate_lock = threading.Lock()

    def terminate() -> None:
        with terminate_lock:
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError:
                    if process.poll() is None:
                        process.kill()
            elif process.poll() is None:
                process.kill()

    writer_error: list[OSError] = []

    def write_input() -> None:
        if input_bytes is None or process.stdin is None:
            return
        try:
            remaining = memoryview(input_bytes)
            while remaining:
                written = process.stdin.write(remaining)
                if written is None or written == 0:
                    raise OSError
                remaining = remaining[written:]
        except BrokenPipeError:
            pass
        except OSError as error:
            writer_error.append(error)
            terminate()
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass

    output_result: list[bytes] = []
    reader_error: list[OSError | RuntimeError] = []

    def read_output() -> None:
        if process.stdout is None:
            reader_error.append(RuntimeError(error_message))
            terminate()
            return
        output = bytearray()
        try:
            while chunk := process.stdout.read(65536):
                output.extend(chunk)
                if len(output) > _MAX_IO_BYTES:
                    raise RuntimeError(error_message)
            output_result.append(bytes(output))
        except (OSError, RuntimeError) as error:
            reader_error.append(error)
            terminate()

    writer = threading.Thread(target=write_input, daemon=True)
    reader = threading.Thread(target=read_output, daemon=True)
    writer.start()
    reader.start()
    returncode: int | None = None
    wait_error: subprocess.TimeoutExpired | None = None
    try:
        returncode = process.wait(timeout=_PROCESS_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        wait_error = error
    finally:
        terminate()
        if process.poll() is None:
            try:
                process.wait(timeout=_CLEANUP_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                pass
        cleanup_deadline = time.monotonic() + _CLEANUP_GRACE_SECONDS
        writer.join(max(0.0, cleanup_deadline - time.monotonic()))
        reader.join(max(0.0, cleanup_deadline - time.monotonic()))
        if process.stdin is not None and not process.stdin.closed:
            try:
                process.stdin.close()
            except OSError:
                pass
        if process.stdout is not None and not process.stdout.closed:
            try:
                process.stdout.close()
            except OSError:
                pass
    if (
        wait_error is not None
        or process.poll() is None
        or writer.is_alive()
        or reader.is_alive()
        or writer_error
        or reader_error
        or len(output_result) != 1
        or returncode is None
    ):
        raise RuntimeError(error_message) from wait_error
    output = output_result[0]
    try:
        result = json.loads(output.decode())
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(error_message) from error
    if not isinstance(result, dict):
        raise RuntimeError(error_message)
    return returncode, result


def _run(
    arguments: list[str], payload: dict[str, Any] | None = None
) -> tuple[int, dict[str, Any]]:
    return _invoke([_binary(), *arguments], payload, "praefectus command failed")


def _run_host_executor(request: dict[str, Any]) -> dict[str, Any]:
    bridge = os.environ.get("PRAEFECTUS_HOST_EXECUTOR")
    if not bridge:
        raise RuntimeError("host executor is not configured")
    returncode, result = _invoke(
        [bridge], {"operation": "execute", "request": request}, "host executor failed"
    )
    if returncode != 0:
        raise RuntimeError("host executor failed")
    return result


def _only(value: dict[str, Any], keys: tuple[str, ...]) -> bool:
    return all(key in keys for key in value)


def _receipt(receipt: Any) -> dict[str, Any] | None:
    if (
        not isinstance(receipt, dict)
        or not _only(
            receipt,
            (
                "protocol_version",
                "action_name",
                "action_hash",
                "started_at_ms",
                "finished_at_ms",
                "backend",
                "fallback_chain",
                "delivery_route",
                "session_isolation",
                "interaction_mode",
                "context_preservation",
                "effect",
                "before",
                "after",
                "warnings",
            ),
        )
        or receipt.get("protocol_version") != 2
        or receipt.get("action_name") not in ("invoke", "set_value", "unknown")
        or not isinstance(receipt.get("action_hash"), str)
        or re.fullmatch(r"[0-9a-f]{64}", receipt["action_hash"]) is None
        or not isinstance(receipt.get("started_at_ms"), int)
        or isinstance(receipt.get("started_at_ms"), bool)
        or receipt["started_at_ms"] < 0
        or not isinstance(receipt.get("finished_at_ms"), int)
        or isinstance(receipt.get("finished_at_ms"), bool)
        or receipt["finished_at_ms"] < receipt["started_at_ms"]
        or not isinstance(receipt.get("backend"), str)
        or re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", receipt["backend"]) is None
        or not isinstance(receipt.get("fallback_chain"), list)
        or not all(
            isinstance(item, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", item)
            for item in receipt["fallback_chain"]
        )
        or receipt.get("delivery_route") not in ("target_addressed", "unknown")
        or receipt.get("session_isolation")
        not in ("shared_desktop", "host_isolated", "unknown")
        or receipt.get("interaction_mode")
        not in ("interactive", "background_only", "unknown")
        or receipt.get("context_preservation")
        not in (
            "not_applicable",
            "unchanged_at_boundaries",
            "changed",
            "unavailable",
            "host_isolated",
        )
        or (
            receipt.get("interaction_mode") == "interactive"
            and receipt.get("context_preservation") != "not_applicable"
        )
        or (
            receipt.get("interaction_mode") == "background_only"
            and receipt.get("session_isolation") == "host_isolated"
            and receipt.get("context_preservation") != "host_isolated"
        )
        or (
            receipt.get("interaction_mode") == "background_only"
            and receipt.get("session_isolation") == "shared_desktop"
            and receipt.get("context_preservation") == "host_isolated"
        )
        or receipt.get("effect") not in ("verified", "executed_unverified", "unknown")
        or "before" not in receipt
        or (receipt["before"] is not None and not isinstance(receipt["before"], dict))
        or "after" not in receipt
        or (receipt["after"] is not None and not isinstance(receipt["after"], dict))
        or not isinstance(receipt.get("warnings"), list)
        or not all(isinstance(item, str) for item in receipt["warnings"])
    ):
        return None
    return {
        key: receipt[key]
        for key in (
            "protocol_version",
            "action_name",
            "action_hash",
            "started_at_ms",
            "finished_at_ms",
            "backend",
            "delivery_route",
            "session_isolation",
            "interaction_mode",
            "context_preservation",
            "effect",
        )
    }


def _valid_receipt_context(receipt: dict[str, Any], terminal_kind: Any) -> bool:
    if _is_recovery_receipt(receipt, terminal_kind):
        return True
    if "unknown" in (
        receipt.get("action_name"),
        receipt.get("delivery_route"),
        receipt.get("session_isolation"),
        receipt.get("interaction_mode"),
    ):
        return False
    if receipt.get("interaction_mode") == "interactive":
        return receipt.get("context_preservation") == "not_applicable"
    if receipt.get("session_isolation") == "host_isolated":
        return receipt.get("context_preservation") == "host_isolated"
    if receipt.get("session_isolation") != "shared_desktop":
        return False
    if terminal_kind == "succeeded" or receipt.get("effect") != "unknown":
        return receipt.get("context_preservation") == "unchanged_at_boundaries"
    return receipt.get("context_preservation") in (
        "not_applicable",
        "unchanged_at_boundaries",
        "changed",
        "unavailable",
    )


def _valid_terminal_effect(receipt: dict[str, Any], terminal_kind: Any) -> bool:
    if terminal_kind == "succeeded":
        return (
            receipt.get("action_name") == "invoke"
            and receipt.get("effect") in ("executed_unverified", "verified")
        ) or (
            receipt.get("action_name") == "set_value"
            and receipt.get("effect") == "verified"
        )
    return terminal_kind == "outcome_unknown"


def _is_recovery_receipt(receipt: dict[str, Any], terminal_kind: Any) -> bool:
    return (
        terminal_kind == "outcome_unknown"
        and receipt.get("effect") == "unknown"
        and receipt.get("context_preservation") == "unavailable"
        and "unknown"
        in (
            receipt.get("action_name"),
            receipt.get("delivery_route"),
            receipt.get("session_isolation"),
            receipt.get("interaction_mode"),
        )
    )


def _ack(
    acknowledgement: Any, expected_operation_id: str | None = None
) -> dict[str, Any] | None:
    if (
        not isinstance(acknowledgement, dict)
        or not _only(
            acknowledgement,
            (
                "protocol_version",
                "operation_id",
                "sequence",
                "action_hash",
                "replayed",
                "state",
            ),
        )
        or acknowledgement.get("protocol_version") != 2
        or not isinstance(acknowledgement.get("operation_id"), str)
        or re.fullmatch(r"[A-Za-z0-9_:-]{1,256}", acknowledgement["operation_id"])
        is None
        or (
            expected_operation_id is not None
            and acknowledgement["operation_id"] != expected_operation_id
        )
        or not isinstance(acknowledgement.get("sequence"), int)
        or isinstance(acknowledgement.get("sequence"), bool)
        or not 0 <= acknowledgement["sequence"] <= 2
        or not isinstance(acknowledgement.get("action_hash"), str)
        or re.fullmatch(r"[0-9a-f]{64}", acknowledgement["action_hash"]) is None
        or not isinstance(acknowledgement.get("replayed"), bool)
    ):
        return None
    result = {
        key: acknowledgement[key]
        for key in (
            "protocol_version",
            "operation_id",
            "sequence",
            "action_hash",
            "replayed",
        )
    }
    state = acknowledgement.get("state", {})
    if not isinstance(state, dict):
        return None
    kind = state.get("kind")
    if kind not in ("accepted", "executing", "terminal"):
        return None
    if (
        (kind == "accepted" and acknowledgement["sequence"] != 0)
        or (kind == "executing" and acknowledgement["sequence"] != 1)
        or (kind == "terminal" and acknowledgement["sequence"] != 2)
    ):
        return None
    result["state"] = kind
    if kind != "terminal":
        return result if _only(state, ("kind",)) else None
    if not _only(state, ("kind", "terminal")):
        return None
    if kind == "terminal":
        terminal = state.get("terminal", {})
        if not isinstance(terminal, dict) or terminal.get("kind") not in (
            "succeeded",
            "rejected",
            "failed",
            "cancelled_before_effect",
            "expired_before_effect",
            "outcome_unknown",
        ):
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
        if "code" in terminal and terminal.get("code") not in (
            "invalid_request",
            "conflict",
            "stale_target",
            "target_not_found",
            "permission_denied",
            "unsupported",
            "dispatch_failed",
            "verification_failed",
        ):
            return None
        if "code" in terminal:
            terminal_result["code"] = terminal["code"]
        if "receipt" in terminal:
            receipt = _receipt(terminal["receipt"])
            if receipt is None:
                return None
            if not _valid_terminal_effect(
                receipt, terminal["kind"]
            ) or not _valid_receipt_context(receipt, terminal["kind"]):
                return None
            terminal_result["receipt"] = receipt
        if (
            terminal.get("kind") in ("succeeded", "outcome_unknown")
            and "receipt" not in terminal_result
        ):
            return None
        if (
            terminal.get("kind") in ("rejected", "failed")
            and "code" not in terminal_result
        ):
            return None
        if terminal.get("kind") in ("rejected", "failed", "outcome_unknown") and (
            not isinstance(terminal.get("message"), str)
            or len(terminal["message"]) > 1024
        ):
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
        redacted = {
            "ok": False,
            "error": {
                "code": code
                if isinstance(code, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code)
                else "praefectus_error"
            },
        }
        if result.get("retry_safe") is False:
            redacted["retry_safe"] = False
        return redacted
    if isinstance(result.get("acknowledgements"), list):
        acknowledgements = [
            _ack(item, expected_operation_id) for item in result["acknowledgements"]
        ]
        return (
            {"acknowledgements": acknowledgements}
            if acknowledgements and all(item is not None for item in acknowledgements)
            else {"error": {"code": "praefectus_error"}}
        )
    if isinstance(result.get("state"), dict):
        return _ack(result, expected_operation_id) or {
            "error": {"code": "praefectus_error"}
        }
    if isinstance(result.get("error"), dict):
        code = result["error"].get("code")
        redacted = {
            "error": {
                "code": code
                if isinstance(code, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code)
                else "praefectus_error"
            }
        }
        if result.get("retry_safe") is False:
            redacted["retry_safe"] = False
        return redacted
    if set(result) != {
        "platform",
        "backend",
        "session_isolation",
        "supported_actions",
        "action_capabilities",
        "permissions",
        "display_geometry_hash",
    }:
        return {"error": {"code": "praefectus_error"}}
    platform = result.get("platform")
    backend = result.get("backend")
    session_isolation = result.get("session_isolation")
    display_geometry_hash = result.get("display_geometry_hash")
    supported_actions = result.get("supported_actions")
    action_capabilities = result.get("action_capabilities")
    permissions = result.get("permissions")
    pairs = {
        "macos": "praefectus-macos-ax",
        "windows": "praefectus-windows-uia",
        "linux": "praefectus-atspi2",
        "browser": "praefectus-chromium-cdp",
    }
    native_permissions = {
        "accessibility",
        "coordinate_capture",
        "private_state",
        "screen_recording",
    }
    linux_permissions = native_permissions | {"atspi2", "display_geometry"}
    permission_shapes = {
        "macos": (native_permissions,),
        "windows": (native_permissions,),
        "linux": (linux_permissions, linux_permissions | {"wayland", "x11"}),
        "browser": ({"cdp", "coordinates", "root_frame_only", "screenshots"},),
    }
    if (
        not isinstance(platform, str)
        or pairs.get(platform) != backend
        or session_isolation not in ("shared_desktop", "host_isolated", "unknown")
        or not isinstance(display_geometry_hash, str)
        or re.fullmatch(r"[0-9a-f]{64}", display_geometry_hash) is None
        or not isinstance(supported_actions, list)
        or len(supported_actions) > 4
        or not all(isinstance(action, str) for action in supported_actions)
        or len(supported_actions) != len(set(supported_actions))
        or not isinstance(action_capabilities, list)
        or len(action_capabilities) > 4
        or not isinstance(permissions, dict)
        or not all(isinstance(allowed, bool) for allowed in permissions.values())
        or set(permissions) not in permission_shapes.get(platform, ())
    ):
        return {"error": {"code": "praefectus_error"}}
    allowed_actions = (
        {"invoke", "scroll", "set_value"}
        if platform in ("windows", "browser")
        else {"invoke", "set_value"}
    )
    background_support = "host_isolated_only" if platform == "browser" else "guarded"
    facts = []
    for fact in action_capabilities:
        if (
            not isinstance(fact, dict)
            or set(fact) != {"action", "delivery_route", "background_support"}
            or fact.get("action") not in allowed_actions
            or fact.get("delivery_route") != "target_addressed"
            or fact.get("background_support") != background_support
        ):
            return {"error": {"code": "praefectus_error"}}
        facts.append(fact["action"])
    if (
        not set(supported_actions).issubset(allowed_actions)
        or len(facts) != len(set(facts))
        or len(supported_actions) != len(facts)
        or set(supported_actions) != set(facts)
    ):
        return {"error": {"code": "praefectus_error"}}
    return {
        "platform": platform,
        "backend": backend,
        "session_isolation": session_isolation,
        "supported_actions": [
            action for action in supported_actions if action in ("invoke", "set_value")
        ],
        "action_capabilities": [
            fact
            for fact in action_capabilities
            if fact["action"] in ("invoke", "set_value")
        ],
        "permissions": permissions,
        "display_geometry_hash": display_geometry_hash,
    }


def _valid_execution(result: dict[str, Any], request: dict[str, Any]) -> bool:
    data = result.get("data") if result.get("ok") is True else result
    action = request.get("action")
    verification = request.get("verification")
    acknowledgements = data.get("acknowledgements") if isinstance(data, dict) else None
    if (
        not isinstance(action, dict)
        or not isinstance(verification, dict)
        or not isinstance(acknowledgements, list)
        or not acknowledgements
    ):
        return False
    action_hash = (
        acknowledgements[0].get("action_hash")
        if isinstance(acknowledgements[0], dict)
        else None
    )
    previous_sequence = -1
    for index, acknowledgement in enumerate(acknowledgements):
        sequence = (
            acknowledgement.get("sequence")
            if isinstance(acknowledgement, dict)
            else None
        )
        if (
            not isinstance(acknowledgement, dict)
            or acknowledgement.get("action_hash") != action_hash
            or not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or sequence <= previous_sequence
            or (
                acknowledgement.get("state") == "terminal"
                and index != len(acknowledgements) - 1
            )
        ):
            return False
        previous_sequence = sequence
    terminal = acknowledgements[-1].get("terminal")
    if acknowledgements[-1].get("state") != "terminal" or not isinstance(
        terminal, dict
    ):
        return False
    receipt = terminal.get("receipt")
    if receipt is None:
        return True
    if (
        not isinstance(receipt, dict)
        or receipt.get("action_hash") != action_hash
        or (
            not _is_recovery_receipt(receipt, terminal.get("kind"))
            and (
                receipt.get("action_name") != action.get("kind")
                or receipt.get("delivery_route") != "target_addressed"
                or receipt.get("interaction_mode") != request.get("interaction_mode")
            )
        )
    ):
        return False
    if terminal.get("kind") == "outcome_unknown":
        effect = receipt.get("effect")
        if effect == "unknown":
            return True
        if action.get("kind") == "invoke":
            return (
                verification.get("kind") == "none" and effect == "executed_unverified"
            )
        return (
            action.get("kind") == "set_value"
            and verification.get("kind") == "target_value_hash"
            and effect in ("executed_unverified", "verified")
        )
    if terminal.get("kind") != "succeeded":
        return True
    return (
        action.get("kind") == "invoke"
        and verification.get("kind") == "none"
        and receipt.get("effect") == "executed_unverified"
    ) or (
        action.get("kind") == "set_value"
        and verification.get("kind") == "target_value_hash"
        and receipt.get("effect") == "verified"
    )


def _valid_proposal(args: Any) -> bool:
    keys = {
        "operation_id",
        "action",
        "target",
        "interaction_mode",
        "deadline_at_ms",
        "verification",
        "verification_version",
        "safety",
    }
    if not isinstance(args, dict) or set(args) != keys:
        return False
    if (
        not isinstance(args["operation_id"], str)
        or re.fullmatch(r"[A-Za-z0-9_:-]{1,256}", args["operation_id"]) is None
    ):
        return False
    deadline = args["deadline_at_ms"]
    version = args["verification_version"]
    if (
        not isinstance(deadline, int)
        or isinstance(deadline, bool)
        or not 1 <= deadline <= _MAX_SAFE_INTEGER
        or not isinstance(version, int)
        or isinstance(version, bool)
        or version != 2
        or args["interaction_mode"] not in ("interactive", "background_only")
        or args["safety"] not in ("reversible", "external", "destructive")
    ):
        return False
    target = args["target"]
    if (
        not isinstance(target, dict)
        or set(target) != {"kind", "target"}
        or target.get("kind") != "element"
    ):
        return False
    semantic = target.get("target")
    semantic_keys = {
        "observation_id",
        "generation",
        "provenance_hash",
        "element_id",
        "fingerprint_hash",
    }
    if not isinstance(semantic, dict) or set(semantic) != semantic_keys:
        return False
    generation = semantic.get("generation")
    if (
        not isinstance(generation, int)
        or isinstance(generation, bool)
        or not 1 <= generation <= _MAX_SAFE_INTEGER
    ):
        return False
    if any(
        not isinstance(semantic[key], str)
        or re.fullmatch(r"[0-9a-f]{64}", semantic[key]) is None
        for key in semantic_keys - {"generation"}
    ):
        return False
    action = args["action"]
    verification = args["verification"]
    if not isinstance(action, dict) or not isinstance(verification, dict):
        return False
    if action == {"kind": "invoke"}:
        return verification == {"kind": "none"}
    if (
        action.get("kind") != "set_value"
        or set(action) != {"kind", "value"}
        or not isinstance(action.get("value"), str)
    ):
        return False
    try:
        value_bytes = action["value"].encode("utf-8")
    except UnicodeEncodeError:
        return False
    if len(value_bytes) > _MAX_VALUE_BYTES:
        return False
    value_hash = hashlib.sha256(value_bytes).hexdigest()
    return (
        set(verification) == {"kind", "sha256"}
        and verification.get("kind") == "target_value_hash"
        and isinstance(verification.get("sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", verification["sha256"]) is not None
        and value_hash == verification["sha256"]
    )


def _execute(args: dict[str, Any], **_: Any) -> str:
    if not _valid_proposal(args):
        return json.dumps({"error": {"code": "invalid_request"}, "retry_safe": False})
    request: dict[str, Any] = {
        key: args[key]
        for key in (
            "operation_id",
            "action",
            "target",
            "interaction_mode",
            "deadline_at_ms",
            "verification",
            "verification_version",
            "safety",
        )
        if key in args
    }
    try:
        result: dict[str, Any] = _redact(
            _run_host_executor(request), args.get("operation_id")
        )
        if "error" not in result and not _valid_execution(result, args):
            result = {"error": {"code": "praefectus_error"}}
        if "error" in result:
            result["retry_safe"] = False
        return json.dumps(result)
    except (TypeError, ValueError, RuntimeError):
        return json.dumps(
            {"error": {"code": "host_executor_unavailable"}, "retry_safe": False}
        )


def _status(args: dict[str, Any], **_: Any) -> str:
    try:
        _returncode, result = _run(["status", args["operation_id"]])
        return json.dumps(_redact(result, args["operation_id"]))
    except (KeyError, TypeError, ValueError, RuntimeError):
        return tool_error("Praefectus status is unavailable")


def _capabilities(args: dict[str, Any], **_: Any) -> str:
    try:
        _returncode, result = _run(["capabilities"])
        return json.dumps(_redact(result))
    except (TypeError, ValueError, RuntimeError):
        return tool_error("Praefectus capabilities are unavailable")


def register(ctx: Any) -> None:
    for name, schema, handler in (
        ("praefectus_execute", EXECUTE_SCHEMA, _execute),
        ("praefectus_status", STATUS_SCHEMA, _status),
        ("praefectus_capabilities", CAPABILITIES_SCHEMA, _capabilities),
    ):
        ctx.register_tool(
            name=name,
            toolset="praefectus",
            schema=schema,
            handler=handler,
            check_fn=_available,
        )
