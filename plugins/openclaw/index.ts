import { Type } from "typebox";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import {
  runHostExecutor,
  runPraefectus,
  type HostExecutor,
  type PraefectusOptions,
} from "./cli.ts";

const NonEmpty = Type.String({ minLength: 1 });
const Identifier = Type.String({
  minLength: 1,
  maxLength: 256,
  pattern: "^[A-Za-z0-9_:-]+$",
});
const Hash = Type.String({
  minLength: 64,
  maxLength: 64,
  pattern: "^[0-9A-Fa-f]+$",
});
const SnapshotId = Type.String({
  minLength: 1,
  maxLength: 256,
  pattern: "^[^\\x00-\\x1F\\x7F-\\x9F]+$",
});
const Key = Type.String({ minLength: 1, maxLength: 64 });
const Timestamp = Type.Integer({ minimum: 1 });
const Target = Type.Union([
  Type.Object(
    {
      kind: Type.Literal("coordinates"),
      x: Type.Integer(),
      y: Type.Integer(),
      display_id: Type.String({ minLength: 1, maxLength: 256 }),
      display_geometry_hash: Hash,
      snapshot_id: SnapshotId,
      snapshot_content_hash: Hash,
    },
    { additionalProperties: false },
  ),
  Type.Object(
    {
      kind: Type.Literal("element"),
      selector: Type.String({ minLength: 1, maxLength: 1024 }),
      snapshot_id: SnapshotId,
      element_fingerprint: Type.Object(
        {
          backend: NonEmpty,
          id: NonEmpty,
          app: NonEmpty,
          process_id: Type.Integer({ minimum: 1 }),
          window: NonEmpty,
          role: NonEmpty,
          label: Type.String(),
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
  ),
  Type.Object({ kind: Type.Literal("none") }, { additionalProperties: false }),
]);
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
          return result(await run("status", params.operation_id, options));
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
        try {
          return result(await hostExecutor(requestForHost(params)));
        } catch {
          return result({
            error: { code: "host_executor_unavailable" },
            retry_safe: false,
          });
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
