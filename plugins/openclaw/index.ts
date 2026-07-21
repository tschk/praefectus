import { Type } from "typebox";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import {
  runHostExecutor,
  runPraefectus,
  type HostExecutor,
  type PraefectusOptions,
} from "./cli.ts";

const NonEmpty = Type.String({ minLength: 1 });
const Timestamp = Type.Integer();
const Target = Type.Union([
  Type.Object(
    {
      kind: Type.Literal("coordinates"),
      x: Type.Integer(),
      y: Type.Integer(),
      display_id: NonEmpty,
      display_geometry_hash: NonEmpty,
      snapshot_id: NonEmpty,
      snapshot_content_hash: NonEmpty,
    },
    { additionalProperties: false },
  ),
  Type.Object(
    {
      kind: Type.Literal("element"),
      selector: NonEmpty,
      snapshot_id: NonEmpty,
      element_fingerprint: Type.Object(
        {
          backend: NonEmpty,
          id: NonEmpty,
          app: NonEmpty,
          process_id: Type.Integer({ minimum: 0 }),
          window: NonEmpty,
          role: Type.String(),
          label: Type.String(),
          bounds: Type.Union([
            Type.Object(
              {
                x: Type.Integer(),
                y: Type.Integer(),
                width: Type.Integer(),
                height: Type.Integer(),
              },
              { additionalProperties: false },
            ),
            Type.Null(),
          ]),
        },
        { additionalProperties: false },
      ),
    },
    { additionalProperties: false },
  ),
  Type.Object({ kind: Type.Literal("none") }, { additionalProperties: false }),
]);
const Delay = Type.Optional(Type.Integer({ minimum: 0 }));
const Action = Type.Union([
  Type.Object(
    {
      kind: Type.Literal("click"),
      button: Type.Union([
        Type.Literal("left"),
        Type.Literal("right"),
        Type.Literal("middle"),
      ]),
      count: Type.Integer({ minimum: 1 }),
      allow_coordinate_fallback: Type.Boolean(),
    },
    { additionalProperties: false },
  ),
  Type.Object(
    {
      kind: Type.Literal("type_text"),
      text: Type.String(),
      clear: Type.Boolean(),
      press_return: Type.Boolean(),
      delay_ms: Delay,
    },
    { additionalProperties: false },
  ),
  Type.Object(
    {
      kind: Type.Literal("press"),
      key: NonEmpty,
      count: Type.Integer({ minimum: 1 }),
      delay_ms: Delay,
    },
    { additionalProperties: false },
  ),
  Type.Object(
    { kind: Type.Literal("paste"), text: Type.String() },
    { additionalProperties: false },
  ),
  Type.Object(
    {
      kind: Type.Literal("hotkey"),
      keys: Type.Array(NonEmpty, { minItems: 1 }),
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
      amount: Type.Integer({ minimum: 1 }),
    },
    { additionalProperties: false },
  ),
  Type.Object({ kind: Type.Literal("move") }, { additionalProperties: false }),
  Type.Object(
    { kind: Type.Literal("set_value"), value: Type.String() },
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
    operation_id: NonEmpty,
    action: Action,
    target: Target,
    deadline_at_ms: Timestamp,
    verification: Verification,
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
        return [
          key,
          isObject(item) && typeof item.code === "string"
            ? { code: item.code }
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

function retrySafe(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(retrySafe);
  if (!isObject(value)) return value;
  const safe = Object.fromEntries(
    Object.entries(value).map(([key, item]) => [key, retrySafe(item)]),
  );
  return safe.kind === "outcome_unknown"
    ? { ...safe, retry_safe: false }
    : safe;
}

function result(value: unknown) {
  const safe = jsonSafe(retrySafe(value));
  return {
    content: [{ type: "text" as const, text: JSON.stringify(safe) }],
    details: safe,
  };
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
        return result(await run("capabilities", undefined, options));
      },
    },
    {
      name: "praefectus_status",
      label: "Praefectus operation status",
      description: "Read the durable status of one Praefectus operation",
      parameters: Type.Object(
        { operation_id: NonEmpty },
        { additionalProperties: false },
      ),
      async execute(_id: string, params: { operation_id: string }) {
        return result(await run("status", params.operation_id, options));
      },
    },
    {
      name: "praefectus_execute",
      label: "Execute approved desktop action",
      description:
        "Submit one action to the host approval bridge; the model cannot supply authority",
      parameters: Request,
      async execute(_id: string, params: unknown) {
        try {
          return result(await hostExecutor(requestForHost(params)));
        } catch {
          return result({ error: { code: "host_executor_unavailable" } });
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
