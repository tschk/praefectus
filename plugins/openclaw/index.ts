import { createHash } from "node:crypto";
import { Type } from "typebox";
import { Value } from "typebox/value";
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
const Hash = Type.String({
  minLength: 64,
  maxLength: 64,
  pattern: "^[0-9a-f]{64}$",
});
const Timestamp = Type.Integer({
  minimum: 1,
  maximum: Number.MAX_SAFE_INTEGER,
});
const Target = Type.Object(
  {
    kind: Type.Literal("element"),
    target: Type.Object(
      {
        observation_id: Hash,
        generation: Type.Integer({
          minimum: 1,
          maximum: Number.MAX_SAFE_INTEGER,
        }),
        provenance_hash: Hash,
        element_id: Hash,
        fingerprint_hash: Hash,
      },
      { additionalProperties: false },
    ),
  },
  { additionalProperties: false },
);
const InvokeAction = Type.Object(
  { kind: Type.Literal("invoke") },
  { additionalProperties: false },
);
const SetValueAction = Type.Object(
  {
    kind: Type.Literal("set_value"),
    value: Type.String({ maxLength: 16384 }),
  },
  { additionalProperties: false },
);
const NoVerification = Type.Object(
  { kind: Type.Literal("none") },
  { additionalProperties: false },
);
const ValueVerification = Type.Object(
  {
    kind: Type.Literal("target_value_hash"),
    sha256: Hash,
  },
  { additionalProperties: false },
);
const Request = Type.Object(
  {
    operation_id: Identifier,
    action: Type.Union([InvokeAction, SetValueAction]),
    target: Target,
    interaction_mode: Type.Union([
      Type.Literal("interactive"),
      Type.Literal("background_only"),
    ]),
    deadline_at_ms: Timestamp,
    verification: Type.Union([NoVerification, ValueVerification]),
    verification_version: Type.Literal(2),
    safety: Type.Union([
      Type.Literal("reversible"),
      Type.Literal("external"),
      Type.Literal("destructive"),
    ]),
  },
  {
    additionalProperties: false,
    oneOf: [
      { properties: { action: InvokeAction, verification: NoVerification } },
      {
        properties: {
          action: SetValueAction,
          verification: ValueVerification,
        },
      },
    ],
  },
);

const RedactedKeys = new Set([
  "authority",
  "authority_ref",
  "authorization",
  "clipboard",
  "credential",
  "error",
  "evidence",
  "element_id",
  "expected",
  "fallback_chain",
  "fingerprint_hash",
  "issuer",
  "key",
  "locator",
  "message",
  "name",
  "observation_id",
  "password",
  "provenance_hash",
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
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
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
      "delivery_route",
      "session_isolation",
      "interaction_mode",
      "context_preservation",
      "effect",
      "before",
      "after",
      "warnings",
    ]) ||
    value.protocol_version !== 2 ||
    !["invoke", "set_value", "unknown"].includes(String(value.action_name)) ||
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
    !["target_addressed", "unknown"].includes(String(value.delivery_route)) ||
    !["shared_desktop", "host_isolated", "unknown"].includes(
      String(value.session_isolation),
    ) ||
    !["interactive", "background_only", "unknown"].includes(
      String(value.interaction_mode),
    ) ||
    ![
      "not_applicable",
      "unchanged_at_boundaries",
      "changed",
      "unavailable",
      "host_isolated",
    ].includes(String(value.context_preservation)) ||
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
    delivery_route: value.delivery_route,
    session_isolation: value.session_isolation,
    interaction_mode: value.interaction_mode,
    context_preservation: value.context_preservation,
    effect: value.effect,
  };
}

function validTerminalEffect(
  receipt: Record<string, unknown>,
  terminalKind: unknown,
): boolean {
  if (terminalKind === "succeeded")
    return (
      (receipt.action_name === "invoke" &&
        ["executed_unverified", "verified"].includes(String(receipt.effect))) ||
      (receipt.action_name === "set_value" && receipt.effect === "verified")
    );
  return terminalKind === "outcome_unknown";
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
    value.protocol_version !== 2 ||
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
      !validTerminalEffect(safeReceipt, terminal.kind) ||
      !validReceiptContext(safeReceipt, terminal.kind)
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
  if (
    !hasOnlyKeys(value, [
      "platform",
      "backend",
      "supported_actions",
      "action_capabilities",
      "permissions",
      "display_geometry_hash",
    ]) ||
    !["macos", "windows", "linux", "browser"].includes(
      String(value.platform),
    ) ||
    ![
      ["macos", "praefectus-macos-ax"],
      ["windows", "praefectus-windows-uia"],
      ["linux", "praefectus-atspi2"],
      ["browser", "praefectus-chromium-cdp"],
    ].some(
      ([platform, backend]) =>
        value.platform === platform && value.backend === backend,
    ) ||
    !isHash(value.display_geometry_hash) ||
    !Array.isArray(value.supported_actions) ||
    value.supported_actions.length > 4 ||
    !value.supported_actions.every((action) =>
      ["invoke", "scroll", "set_value"].includes(String(action)),
    ) ||
    new Set(value.supported_actions).size !== value.supported_actions.length ||
    !Array.isArray(value.action_capabilities) ||
    value.action_capabilities.length > 4 ||
    !isObject(value.permissions) ||
    Object.keys(value.permissions).length > 8
  )
    return { error: { code: "praefectus_error" } };
  const supportedActions = value.supported_actions;
  const actionCapabilities = value.action_capabilities;
  const permissions = value.permissions;
  const allowedPermissions =
    value.platform === "browser"
      ? ["cdp", "coordinates", "root_frame_only", "screenshots"]
      : value.platform === "linux"
        ? [
            "accessibility",
            "atspi2",
            "coordinate_capture",
            "display_geometry",
            "private_state",
            "screen_recording",
            "wayland",
            "x11",
          ]
        : [
            "accessibility",
            "coordinate_capture",
            "private_state",
            "screen_recording",
          ];
  const requiredPermissions =
    value.platform === "browser"
      ? allowedPermissions
      : [
          "accessibility",
          "coordinate_capture",
          "private_state",
          "screen_recording",
          ...(value.platform === "linux" ? ["atspi2", "display_geometry"] : []),
        ];
  const allowedActions =
    value.platform === "browser"
      ? ["invoke", "scroll", "set_value"]
      : value.platform === "windows"
        ? ["invoke", "scroll", "set_value"]
        : ["invoke", "set_value"];
  if (
    !requiredPermissions.every((key) => key in permissions) ||
    !Object.entries(permissions).every(
      ([key, allowed]) =>
        allowedPermissions.includes(key) && typeof allowed === "boolean",
    ) ||
    !supportedActions.every((action) =>
      allowedActions.includes(String(action)),
    ) ||
    !actionCapabilities.every(
      (capability) =>
        isObject(capability) &&
        hasOnlyKeys(capability, [
          "action",
          "delivery_route",
          "background_support",
        ]) &&
        ["invoke", "scroll", "set_value"].includes(String(capability.action)) &&
        capability.delivery_route === "target_addressed" &&
        capability.background_support ===
          (value.platform === "browser" ? "host_isolated_only" : "guarded"),
    )
  )
    return { error: { code: "praefectus_error" } };
  const facts = actionCapabilities.map(
    (capability) => (capability as Record<string, unknown>).action,
  );
  if (
    new Set(facts).size !== facts.length ||
    supportedActions.length !== facts.length ||
    supportedActions.some((action) => !facts.includes(action))
  )
    return { error: { code: "praefectus_error" } };
  return {
    platform: value.platform,
    backend: value.backend,
    supported_actions: supportedActions.filter(
      (action) => action === "invoke" || action === "set_value",
    ),
    action_capabilities: actionCapabilities.filter(
      (capability) =>
        isObject(capability) &&
        ["invoke", "set_value"].includes(String(capability.action)),
    ),
    permissions,
    display_geometry_hash: value.display_geometry_hash,
  };
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
    !isObject(request.verification) ||
    !["interactive", "background_only"].includes(
      String(request.interaction_mode),
    )
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
    (!isRecoveryReceipt(terminal.receipt, terminal.kind) &&
      (terminal.receipt.action_name !== request.action.kind ||
        terminal.receipt.delivery_route !== "target_addressed" ||
        terminal.receipt.interaction_mode !== request.interaction_mode)) ||
    !validReceiptContext(terminal.receipt, terminal.kind)
  )
    return false;
  if (terminal.kind === "outcome_unknown") {
    if (terminal.receipt.effect === "unknown") return true;
    if (request.action.kind === "invoke")
      return (
        request.verification.kind === "none" &&
        terminal.receipt.effect === "executed_unverified"
      );
    return (
      request.action.kind === "set_value" &&
      request.verification.kind === "target_value_hash" &&
      ["executed_unverified", "verified"].includes(
        String(terminal.receipt.effect),
      )
    );
  }
  if (terminal.kind !== "succeeded") return true;
  return request.action.kind === "invoke"
    ? request.verification.kind === "none" &&
        terminal.receipt.effect === "executed_unverified"
    : request.action.kind === "set_value" &&
        request.verification.kind === "target_value_hash" &&
        terminal.receipt.effect === "verified";
}

function validReceiptContext(
  receipt: Record<string, unknown>,
  terminalKind: unknown,
): boolean {
  if (isRecoveryReceipt(receipt, terminalKind)) return true;
  if (
    receipt.action_name === "unknown" ||
    receipt.delivery_route === "unknown" ||
    receipt.session_isolation === "unknown" ||
    receipt.interaction_mode === "unknown"
  )
    return false;
  if (receipt.interaction_mode === "interactive")
    return receipt.context_preservation === "not_applicable";
  if (receipt.session_isolation === "host_isolated")
    return receipt.context_preservation === "host_isolated";
  return (
    receipt.session_isolation === "shared_desktop" &&
    (terminalKind === "succeeded" || receipt.effect !== "unknown"
      ? receipt.context_preservation === "unchanged_at_boundaries"
      : [
          "not_applicable",
          "unchanged_at_boundaries",
          "changed",
          "unavailable",
        ].includes(String(receipt.context_preservation)))
  );
}

function isRecoveryReceipt(
  receipt: Record<string, unknown>,
  terminalKind: unknown,
): boolean {
  return (
    terminalKind === "outcome_unknown" &&
    receipt.effect === "unknown" &&
    receipt.context_preservation === "unavailable" &&
    (receipt.action_name === "unknown" ||
      receipt.delivery_route === "unknown" ||
      receipt.session_isolation === "unknown" ||
      receipt.interaction_mode === "unknown")
  );
}

function validRequest(value: unknown): boolean {
  if (!Value.Check(Request, value) || !isObject(value)) return false;
  const action = value.action as Record<string, unknown>;
  const verification = value.verification as Record<string, unknown>;
  const actionValue = String(action.value);
  return (
    action.kind === "invoke" ||
    (Buffer.from(actionValue, "utf8").toString("utf8") === actionValue &&
      Buffer.byteLength(actionValue, "utf8") <= 16384 &&
      createHash("sha256").update(actionValue, "utf8").digest("hex") ===
        verification.sha256)
  );
}

function requestForHost(value: unknown): unknown {
  if (!isObject(value)) return value;
  return Object.fromEntries(
    Object.entries(value).filter(([key]) =>
      [
        "operation_id",
        "action",
        "target",
        "interaction_mode",
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
        "Submit one interactive or background-only semantic action to the host approval bridge; the model cannot supply authority or isolation",
      parameters: Request,
      async execute(_id: string, params: unknown) {
        const operationId = isObject(params)
          ? String(params.operation_id)
          : undefined;
        if (!validRequest(params))
          return result(
            { error: { code: "invalid_request" }, retry_safe: false },
            operationId,
            params,
          );
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
