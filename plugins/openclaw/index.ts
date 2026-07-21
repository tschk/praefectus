import { Type } from "typebox";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import {
  runHostExecutor,
  runPraefectus,
  type HostExecutor,
  type PraefectusOptions,
} from "./cli.ts";

const Identifier = Type.String({
  minLength: 1,
  maxLength: 256,
  pattern: "^[A-Za-z0-9_:-]+$",
});
const SnapshotId = Type.String({
  minLength: 1,
  maxLength: 256,
  pattern: "^[^\\x00-\\x1F\\x7F-\\x9F]+$",
});
const Key = Type.String({ minLength: 1, maxLength: 64 });
const Timestamp = Type.Integer({ minimum: 1 });
const Target = Type.Object(
  {
    kind: Type.Literal("element"),
    selector: Type.String({ minLength: 1, maxLength: 1024 }),
    snapshot_id: SnapshotId,
    element_fingerprint: Type.Object(
      {
        backend: Type.String({ minLength: 1, maxLength: 128 }),
        id: Type.String({ minLength: 1, maxLength: 512 }),
        app: Type.String({ minLength: 1, maxLength: 256 }),
        process_id: Type.Integer({ minimum: 1 }),
        window: Type.String({ minLength: 1, maxLength: 512 }),
        role: Type.String({ minLength: 1, maxLength: 128 }),
        label: Type.String({ maxLength: 1024 }),
        bounds: Type.Object(
          {
            x: Type.Integer(),
            y: Type.Integer(),
            width: Type.Integer({ minimum: 1 }),
            height: Type.Integer({ minimum: 1 }),
          },
          { additionalProperties: false },
        ),
      },
      { additionalProperties: false },
    ),
  },
  { additionalProperties: false },
);
const Delay = Type.Optional(Type.Integer({ minimum: 0, maximum: 1000 }));
const Action = Type.Union([
  Type.Object(
    {
      kind: Type.Literal("click"),
      button: Type.Union([
        Type.Literal("left"),
        Type.Literal("right"),
        Type.Literal("middle"),
      ]),
      count: Type.Integer({ minimum: 1, maximum: 3 }),
      allow_coordinate_fallback: Type.Boolean(),
    },
    { additionalProperties: false },
  ),
  Type.Object(
    {
      kind: Type.Literal("type_text"),
      text: Type.String({ minLength: 1, maxLength: 16384 }),
      clear: Type.Boolean(),
      press_return: Type.Boolean(),
      delay_ms: Delay,
    },
    { additionalProperties: false },
  ),
  Type.Object(
    {
      kind: Type.Literal("press"),
      key: Key,
      count: Type.Integer({ minimum: 1, maximum: 100 }),
      delay_ms: Delay,
    },
    { additionalProperties: false },
  ),
  Type.Object(
    {
      kind: Type.Literal("paste"),
      text: Type.String({ minLength: 1, maxLength: 16384 }),
    },
    { additionalProperties: false },
  ),
  Type.Object(
    {
      kind: Type.Literal("hotkey"),
      keys: Type.Array(Key, { minItems: 1, maxItems: 8 }),
    },
    { additionalProperties: false },
  ),
  Type.Object(
    {
      kind: Type.Literal("scroll"),
      direction: Type.Union([
        Type.Literal("up"),
        Type.Literal("down"),
        Type.Literal("left"),
        Type.Literal("right"),
      ]),
      amount: Type.Integer({ minimum: 1, maximum: 100 }),
    },
    { additionalProperties: false },
  ),
  Type.Object({ kind: Type.Literal("move") }, { additionalProperties: false }),
  Type.Object(
    {
      kind: Type.Literal("set_value"),
      value: Type.String({ maxLength: 16384 }),
    },
    { additionalProperties: false },
  ),
]);
const Verification = Type.Union([
  Type.Object({ kind: Type.Literal("none") }, { additionalProperties: false }),
  Type.Object(
    { kind: Type.Literal("snapshot_changed") },
    { additionalProperties: false },
  ),
  Type.Object(
    { kind: Type.Literal("target_state"), expected: Type.Unknown() },
    { additionalProperties: false },
  ),
]);
const Request = Type.Object(
  {
    operation_id: Identifier,
    action: Action,
    target: Target,
    deadline_at_ms: Timestamp,
    verification: Verification,
    verification_version: Type.Literal(1),
    safety: Type.Union([
      Type.Literal("reversible"),
      Type.Literal("external"),
      Type.Literal("destructive"),
    ]),
  },
  { additionalProperties: false },
);

const RedactedKeys = new Set([
  "authority",
  "authority_ref",
  "authorization",
  "clipboard",
  "credential",
  "error",
  "evidence",
  "expected",
  "fallback_chain",
  "issuer",
  "key",
  "locator",
  "message",
  "password",
  "screenshot",
  "secret",
  "selector",
  "signed_authority",
  "snapshot",
  "text",
  "token",
  "value",
  "warnings",
]);

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function jsonSafe(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(jsonSafe);
  if (!isObject(value)) return value;
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => {
      if (key === "error") {
        const code = isObject(item) ? item.code : undefined;
        return [
          key,
          typeof code === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(code)
            ? { code }
            : { code: "praefectus_error" },
        ];
      }
      return [
        key,
        RedactedKeys.has(key.toLowerCase()) ? "[REDACTED]" : jsonSafe(item),
      ];
    }),
  );
}

function hasOutcomeUnknown(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(hasOutcomeUnknown);
  if (!isObject(value)) return false;
  return (
    value.kind === "outcome_unknown" ||
    Object.values(value).some(hasOutcomeUnknown)
  );
}

function isHash(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-fA-F]{64}$/.test(value);
}

function isInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value);
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: string[]) {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function receipt(value: unknown): Record<string, unknown> | undefined {
  if (
    !isObject(value) ||
    !hasOnlyKeys(value, [
      "protocol_version",
      "action_name",
      "action_hash",
      "started_at_ms",
      "finished_at_ms",
      "backend",
      "fallback_chain",
      "effect",
      "before",
      "after",
      "warnings",
    ]) ||
    value.protocol_version !== 1 ||
    ![
      "click",
      "type_text",
      "press",
      "paste",
      "hotkey",
      "scroll",
      "move",
      "set_value",
    ].includes(String(value.action_name)) ||
    !isHash(value.action_hash) ||
    !isInteger(value.started_at_ms) ||
    value.started_at_ms < 0 ||
    !isInteger(value.finished_at_ms) ||
    value.finished_at_ms < value.started_at_ms ||
    typeof value.backend !== "string" ||
    !/^[A-Za-z0-9_.:-]{1,128}$/.test(value.backend) ||
    !Array.isArray(value.fallback_chain) ||
    !value.fallback_chain.every(
      (item) =>
        typeof item === "string" && /^[A-Za-z0-9_.:-]{1,128}$/.test(item),
    ) ||
    !["verified", "executed_unverified", "unknown"].includes(
      String(value.effect),
    ) ||
    !("before" in value) ||
    !(value.before === null || isObject(value.before)) ||
    !("after" in value) ||
    !(value.after === null || isObject(value.after)) ||
    !Array.isArray(value.warnings) ||
    !value.warnings.every((item) => typeof item === "string")
  )
    return undefined;
  return {
    protocol_version: value.protocol_version,
    action_name: value.action_name,
    action_hash: value.action_hash,
    started_at_ms: value.started_at_ms,
    finished_at_ms: value.finished_at_ms,
    backend: value.backend,
    effect: value.effect,
  };
}

function acknowledgement(
  value: unknown,
  expectedOperationId?: string,
): Record<string, unknown> | undefined {
  if (
    !isObject(value) ||
    !hasOnlyKeys(value, [
      "protocol_version",
      "operation_id",
      "sequence",
      "action_hash",
      "replayed",
      "state",
    ]) ||
    value.protocol_version !== 1 ||
    typeof value.operation_id !== "string" ||
    !/^[A-Za-z0-9_:-]{1,256}$/.test(value.operation_id) ||
    (expectedOperationId !== undefined &&
      value.operation_id !== expectedOperationId) ||
    !isInteger(value.sequence) ||
    value.sequence < 0 ||
    value.sequence > 2 ||
    !isHash(value.action_hash) ||
    typeof value.replayed !== "boolean" ||
    !isObject(value.state)
  )
    return undefined;
  const kind = value.state.kind;
  if (!["accepted", "executing", "terminal"].includes(String(kind)))
    return undefined;
  if (
    (kind === "accepted" && value.sequence !== 0) ||
    (kind === "executing" && value.sequence !== 1) ||
    (kind === "terminal" && value.sequence !== 2)
  )
    return undefined;
  const safe: Record<string, unknown> = {
    protocol_version: value.protocol_version,
    operation_id: value.operation_id,
    sequence: value.sequence,
    action_hash: value.action_hash,
    replayed: value.replayed,
  };
  safe.state = kind;
  if (kind !== "terminal")
    return hasOnlyKeys(value.state, ["kind"]) ? safe : undefined;
  if (!hasOnlyKeys(value.state, ["kind", "terminal"])) return undefined;
  const terminal = value.state.terminal;
  if (
    !isObject(terminal) ||
    ![
      "succeeded",
      "rejected",
      "failed",
      "cancelled_before_effect",
      "expired_before_effect",
      "outcome_unknown",
    ].includes(String(terminal.kind))
  )
    return undefined;
  const terminalKeys =
    terminal.kind === "succeeded"
      ? ["kind", "receipt"]
      : terminal.kind === "rejected" || terminal.kind === "failed"
        ? ["kind", "code", "message"]
        : terminal.kind === "outcome_unknown"
          ? ["kind", "receipt", "message"]
          : ["kind"];
  if (!hasOnlyKeys(terminal, terminalKeys)) return undefined;
  const terminalResult: Record<string, unknown> = { kind: terminal.kind };
  if ("code" in terminal) {
    if (
      ![
        "invalid_request",
        "conflict",
        "stale_target",
        "target_not_found",
        "permission_denied",
        "unsupported",
        "dispatch_failed",
        "verification_failed",
      ].includes(String(terminal.code))
    )
      return undefined;
    terminalResult.code = terminal.code;
  }
  if ("receipt" in terminal) {
    const safeReceipt = receipt(terminal.receipt);
    if (!safeReceipt) return undefined;
    if (
      (terminal.kind === "succeeded" && safeReceipt.effect === "unknown") ||
      (terminal.kind === "outcome_unknown" && safeReceipt.effect === "verified")
    )
      return undefined;
    terminalResult.receipt = safeReceipt;
  }
  if (
    ["succeeded", "outcome_unknown"].includes(String(terminal.kind)) &&
    !("receipt" in terminalResult)
  )
    return undefined;
  if (
    ["rejected", "failed"].includes(String(terminal.kind)) &&
    !("code" in terminalResult)
  )
    return undefined;
  if (
    ["rejected", "failed", "outcome_unknown"].includes(String(terminal.kind)) &&
    (typeof terminal.message !== "string" || terminal.message.length > 1024)
  )
    return undefined;
  if (terminal.kind === "outcome_unknown") terminalResult.retry_safe = false;
  safe.terminal = terminalResult;
  return safe;
}

function redact(
  value: unknown,
  expectedOperationId?: string,
): Record<string, unknown> {
  if (!isObject(value)) return { error: { code: "praefectus_error" } };
  if (value.ok === true) {
    if (value.data === null) return { ok: true, data: null };
    if (!isObject(value.data)) return { error: { code: "praefectus_error" } };
    const data = redact(value.data, expectedOperationId);
    return "error" in data ? data : { ok: true, data };
  }
  if (value.ok === false || isObject(value.error)) {
    const code = isObject(value.error) ? value.error.code : undefined;
    return {
      ...(value.ok === false ? { ok: false } : {}),
      error: {
        code:
          typeof code === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(code)
            ? code
            : "praefectus_error",
      },
      ...(value.retry_safe === false ? { retry_safe: false } : {}),
    };
  }
  if (Array.isArray(value.acknowledgements)) {
    const acknowledgements = value.acknowledgements.map((item) =>
      acknowledgement(item, expectedOperationId),
    );
    if (!acknowledgements.length || acknowledgements.some((item) => !item))
      return { error: { code: "praefectus_error" } };
    return { acknowledgements };
  }
  if (isObject(value.state)) {
    return (
      acknowledgement(value, expectedOperationId) ?? {
        error: { code: "praefectus_error" },
      }
    );
  }
  const capabilities = Object.fromEntries(
    Object.entries(value).filter(([key, item]) => {
      if (["platform", "backend", "display_geometry_hash"].includes(key))
        return typeof item === "string";
      if (key === "supported_actions")
        return (
          Array.isArray(item) &&
          item.every((action) => typeof action === "string")
        );
      if (key === "permissions")
        return (
          isObject(item) &&
          Object.values(item).every((allowed) => typeof allowed === "boolean")
        );
      return false;
    }),
  );
  return Object.keys(capabilities).length
    ? capabilities
    : { error: { code: "praefectus_error" } };
}

function result(
  value: unknown,
  expectedOperationId?: string,
  executionRequest?: unknown,
) {
  let safe = jsonSafe(redact(value, expectedOperationId)) as Record<
    string,
    unknown
  >;
  if (
    executionRequest !== undefined &&
    !("error" in safe) &&
    !validExecution(safe, executionRequest)
  )
    safe = { error: { code: "praefectus_error" } };
  if (hasOutcomeUnknown(safe)) safe.retry_safe = false;
  if (executionRequest !== undefined && "error" in safe)
    safe.retry_safe = false;
  return {
    content: [{ type: "text" as const, text: JSON.stringify(safe) }],
    details: safe,
  };
}

function validExecution(
  value: Record<string, unknown>,
  request: unknown,
): boolean {
  const data = value.ok === true && isObject(value.data) ? value.data : value;
  if (
    !isObject(request) ||
    !isObject(request.action) ||
    !isObject(request.verification)
  )
    return false;
  const acknowledgements = data.acknowledgements;
  if (!Array.isArray(acknowledgements) || !acknowledgements.length)
    return false;
  const actionHash = acknowledgements[0]?.action_hash;
  let previousSequence = -1;
  for (const item of acknowledgements) {
    if (
      !isObject(item) ||
      item.action_hash !== actionHash ||
      !isInteger(item.sequence) ||
      item.sequence <= previousSequence ||
      (item.state === "terminal" && item !== acknowledgements.at(-1))
    )
      return false;
    previousSequence = item.sequence;
  }
  const terminalAck = acknowledgements.at(-1);
  if (
    !isObject(terminalAck) ||
    terminalAck.state !== "terminal" ||
    !isObject(terminalAck.terminal)
  )
    return false;
  const terminal = terminalAck.terminal;
  if (!("receipt" in terminal)) return true;
  if (
    !isObject(terminal.receipt) ||
    terminal.receipt.action_hash !== actionHash ||
    terminal.receipt.action_name !== request.action.kind
  )
    return false;
  if (terminal.kind !== "succeeded") return true;
  return request.verification.kind === "none"
    ? terminal.receipt.effect === "executed_unverified"
    : request.verification.kind === "target_state" &&
        terminal.receipt.effect === "verified";
}

function requestForHost(value: unknown): unknown {
  if (!isObject(value)) return value;
  return Object.fromEntries(
    Object.entries(value).filter(([key]) =>
      [
        "operation_id",
        "action",
        "target",
        "deadline_at_ms",
        "verification",
        "verification_version",
        "safety",
      ].includes(key),
    ),
  );
}

export function tools(
  options: PraefectusOptions,
  run: typeof runPraefectus = runPraefectus,
  hostExecutor: HostExecutor = (request) => runHostExecutor(request, options),
) {
  return [
    {
      name: "praefectus_capabilities",
      label: "Praefectus capabilities",
      description:
        "Report the desktop actions and permissions exposed by Praefectus",
      parameters: Type.Object({}, { additionalProperties: false }),
      async execute() {
        try {
          return result(await run("capabilities", undefined, options));
        } catch {
          return result({ error: { code: "praefectus_unavailable" } });
        }
      },
    },
    {
      name: "praefectus_status",
      label: "Praefectus operation status",
      description: "Read the durable status of one Praefectus operation",
      parameters: Type.Object(
        { operation_id: Identifier },
        { additionalProperties: false },
      ),
      async execute(_id: string, params: { operation_id: string }) {
        try {
          return result(
            await run("status", params.operation_id, options),
            params.operation_id,
          );
        } catch {
          return result({ error: { code: "praefectus_unavailable" } });
        }
      },
    },
    {
      name: "praefectus_execute",
      label: "Execute approved desktop action",
      description:
        "Submit one action to the host approval bridge; the model cannot supply authority",
      parameters: Request,
      async execute(_id: string, params: unknown) {
        const operationId = isObject(params)
          ? String(params.operation_id)
          : undefined;
        try {
          return result(
            await hostExecutor(requestForHost(params)),
            operationId,
            params,
          );
        } catch {
          return result(
            {
              error: { code: "host_executor_unavailable" },
              retry_safe: false,
            },
            operationId,
            params,
          );
        }
      },
    },
  ];
}

export const praefectusPlugin = definePluginEntry({
  id: "praefectus",
  name: "Praefectus Desktop Actions",
  description:
    "Durable, authority-bound desktop action execution through Praefectus",
  register(api) {
    const options = (api.pluginConfig as PraefectusOptions | undefined) ?? {};
    for (const tool of tools(options)) api.registerTool(tool);
  },
});

export default praefectusPlugin;
