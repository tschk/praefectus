import { createHash } from "node:crypto";
import { describe, expect, test } from "bun:test";
import { Value } from "typebox/value";
import { runHostExecutor } from "./cli.ts";
import { praefectusPlugin, tools } from "./index.ts";

const actionHash = "a".repeat(64);

function semanticTarget() {
  return {
    kind: "element" as const,
    target: {
      observation_id: "1".repeat(64),
      generation: 1,
      provenance_hash: "2".repeat(64),
      element_id: "3".repeat(64),
      fingerprint_hash: "4".repeat(64),
    },
  };
}

function invokeRequest() {
  return {
    operation_id: "operation-1",
    action: { kind: "invoke" as const },
    target: semanticTarget(),
    interaction_mode: "interactive" as const,
    deadline_at_ms: 1,
    verification: { kind: "none" as const },
    verification_version: 2 as const,
    safety: "reversible" as const,
  };
}

function setValueRequest(value = "secret") {
  return {
    ...invokeRequest(),
    action: { kind: "set_value" as const, value },
    verification: {
      kind: "target_value_hash" as const,
      sha256: createHash("sha256").update(value, "utf8").digest("hex"),
    },
  };
}

function outcomeUnknown(operationId = "operation-1") {
  return {
    acknowledgements: [
      {
        protocol_version: 2,
        operation_id: operationId,
        sequence: 2,
        action_hash: actionHash,
        replayed: false,
        state: {
          kind: "terminal",
          terminal: {
            kind: "outcome_unknown",
            message: "unknown outcome",
            receipt: {
              protocol_version: 2,
              action_name: "invoke",
              action_hash: actionHash,
              started_at_ms: 1,
              finished_at_ms: 2,
              backend: "test",
              fallback_chain: [],
              delivery_route: "target_addressed",
              session_isolation: "shared_desktop",
              interaction_mode: "interactive",
              context_preservation: "not_applicable",
              effect: "unknown",
              before: null,
              after: null,
              warnings: [],
            },
          },
        },
      },
    ],
  };
}

function legacyRecovery(operationId = "operation-1") {
  const result = outcomeUnknown(operationId);
  const receipt = result.acknowledgements[0].state.terminal.receipt;
  receipt.action_name = "unknown";
  receipt.delivery_route = "unknown";
  receipt.session_isolation = "unknown";
  receipt.interaction_mode = "unknown";
  receipt.context_preservation = "unavailable";
  return result;
}

function windowsCapabilities() {
  return {
    platform: "windows",
    backend: "praefectus-windows-uia",
    supported_actions: ["invoke", "set_value", "scroll"],
    action_capabilities: [
      {
        action: "invoke",
        delivery_route: "target_addressed",
        background_support: "guarded",
      },
      {
        action: "set_value",
        delivery_route: "target_addressed",
        background_support: "guarded",
      },
      {
        action: "scroll",
        delivery_route: "target_addressed",
        background_support: "guarded",
      },
    ],
    permissions: {
      accessibility: true,
      coordinate_capture: false,
      private_state: true,
      screen_recording: false,
    },
    display_geometry_hash: "a".repeat(64),
  };
}

function cdpCapabilities() {
  return {
    platform: "browser",
    backend: "praefectus-chromium-cdp",
    supported_actions: ["invoke", "scroll", "set_value"],
    action_capabilities: [
      {
        action: "invoke",
        delivery_route: "target_addressed",
        background_support: "host_isolated_only",
      },
      {
        action: "scroll",
        delivery_route: "target_addressed",
        background_support: "host_isolated_only",
      },
      {
        action: "set_value",
        delivery_route: "target_addressed",
        background_support: "host_isolated_only",
      },
    ],
    permissions: {
      cdp: true,
      coordinates: false,
      root_frame_only: true,
      screenshots: false,
    },
    display_geometry_hash: "b".repeat(64),
  };
}

describe("Praefectus OpenClaw tools", () => {
  test("passes only the action request to the host executor", async () => {
    const calls: unknown[][] = [];
    const run = async (...args: unknown[]) => {
      calls.push(args);
      return outcomeUnknown();
    };
    const hostExecutor = async (...args: unknown[]) => {
      calls.push(args);
      return { retry_safe: true, ...outcomeUnknown() };
    };
    const registered = tools({}, run as never, hostExecutor as never);
    const execute = registered.find(
      (tool) => tool.name === "praefectus_execute",
    )!;
    const request = invokeRequest();
    const output = await execute.execute("call-1", request);
    expect(calls).toEqual([[request]]);
    expect(output.details).toEqual({
      acknowledgements: [
        {
          protocol_version: 2,
          operation_id: "operation-1",
          sequence: 2,
          action_hash: actionHash,
          replayed: false,
          state: "terminal",
          terminal: {
            kind: "outcome_unknown",
            receipt: {
              protocol_version: 2,
              action_name: "invoke",
              action_hash: actionHash,
              started_at_ms: 1,
              finished_at_ms: 2,
              backend: "test",
              delivery_route: "target_addressed",
              session_isolation: "shared_desktop",
              interaction_mode: "interactive",
              context_preservation: "not_applicable",
              effect: "unknown",
            },
            retry_safe: false,
          },
        },
      ],
      retry_safe: false,
    });
  });

  test("keeps the manifest and registered tool contracts aligned", async () => {
    const manifest = await Bun.file(
      new URL("./openclaw.plugin.json", import.meta.url),
    ).json();
    const names: string[] = [];
    praefectusPlugin.register({
      pluginConfig: {},
      registerTool(tool: { name: string }) {
        names.push(tool.name);
      },
    } as never);
    expect(names.sort()).toEqual([...manifest.contracts.tools].sort());
  });

  test("requires the core semantic target fence", () => {
    const execute = tools({}).find(
      (tool) => tool.name === "praefectus_execute",
    )!;
    const request = invokeRequest();
    expect(Value.Check(execute.parameters, request)).toBeTrue();
    const { fingerprint_hash: _, ...unfenced } = request.target.target;
    expect(
      Value.Check(execute.parameters, {
        ...request,
        target: { ...request.target, target: unfenced },
      }),
    ).toBeFalse();
  });

  test("rejects caller authority and unsupported actions before the host", async () => {
    const calls: unknown[] = [];
    const execute = tools(
      {},
      async () => ({}),
      async (request) => {
        calls.push(request);
        return outcomeUnknown();
      },
    ).find((tool) => tool.name === "praefectus_execute")!;
    for (const request of [
      { ...invokeRequest(), authority_ref: "caller-authority" },
      { ...invokeRequest(), session_isolation: "host_isolated" },
      { ...invokeRequest(), host_isolation: true },
      { ...invokeRequest(), interaction_mode: "host_isolated" },
      { ...invokeRequest(), interaction_mode: "unknown" },
      { ...invokeRequest(), interaction_mode: undefined },
      {
        ...invokeRequest(),
        action: {
          kind: "click",
          button: "left",
          count: 1,
          allow_coordinate_fallback: false,
        },
      },
      {
        ...invokeRequest(),
        action: {
          kind: "type_text",
          text: "secret",
          clear: false,
          press_return: false,
        },
      },
      {
        ...invokeRequest(),
        action: { ...invokeRequest().action, button: "right" },
      },
      {
        ...invokeRequest(),
        action: { ...invokeRequest().action, count: 2 },
      },
      {
        ...invokeRequest(),
        action: {
          ...invokeRequest().action,
          allow_coordinate_fallback: true,
        },
      },
      { ...invokeRequest(), action: { kind: "press", key: "Enter", count: 1 } },
      { ...invokeRequest(), action: { kind: "paste", text: "secret" } },
      { ...invokeRequest(), action: { kind: "hotkey", keys: ["Meta", "A"] } },
      {
        ...invokeRequest(),
        action: { kind: "scroll", direction: "down", amount: 1 },
      },
      { ...invokeRequest(), action: { kind: "move" } },
      {
        ...invokeRequest(),
        action: { ...invokeRequest().action, button: "middle" },
      },
      {
        ...setValueRequest(),
        verification: {
          kind: "target_value_hash",
          sha256: "a".repeat(64),
        },
      },
      {
        ...invokeRequest(),
        deadline_at_ms: Number.MAX_SAFE_INTEGER + 1,
      },
      setValueRequest("é".repeat(8193)),
      setValueRequest("\ud800"),
    ]) {
      const output = await execute.execute("call-1", request);
      expect(output.details).toEqual({
        error: { code: "invalid_request" },
        retry_safe: false,
      });
    }
    expect(calls).toEqual([]);
  });

  test("rejects arbitrary child output without echoing it", async () => {
    const childOutputs: unknown[] = [
      "backend secret",
      ["backend secret"],
      {
        text: "typed secret",
        name: "semantic secret",
        element_id: "element secret",
        observation_id: "observation secret",
        stderr: "token=secret",
        path: "/Users/private",
        detail: "credential",
        ok: true,
      },
      { ok: true, data: { stderr: "token=secret" } },
    ];
    for (const childOutput of childOutputs) {
      const registered = tools({}, async () => childOutput);
      const capabilities = registered.find(
        (tool) => tool.name === "praefectus_capabilities",
      )!;
      const output = await capabilities.execute("call-1", {} as never);
      expect(output.details).toEqual({ error: { code: "praefectus_error" } });
      expect(JSON.stringify(output.details)).not.toContain("secret");
    }
  });

  test("advertises only the stable semantic effects", async () => {
    const capabilities = tools({}, async () => windowsCapabilities()).find(
      (tool) => tool.name === "praefectus_capabilities",
    )!;
    const output = await capabilities.execute("call-1", {} as never);
    expect(output.details).toEqual({
      platform: "windows",
      backend: "praefectus-windows-uia",
      supported_actions: ["invoke", "set_value"],
      action_capabilities: [
        {
          action: "invoke",
          delivery_route: "target_addressed",
          background_support: "guarded",
        },
        {
          action: "set_value",
          delivery_route: "target_addressed",
          background_support: "guarded",
        },
      ],
      permissions: {
        accessibility: true,
        coordinate_capture: false,
        private_state: true,
        screen_recording: false,
      },
      display_geometry_hash: "a".repeat(64),
    });
  });

  test("rejects mismatched background capability facts", async () => {
    const capabilities = tools({}, async () => ({
      ...windowsCapabilities(),
      supported_actions: ["invoke"],
      action_capabilities: [
        {
          action: "set_value",
          delivery_route: "target_addressed",
          background_support: "guarded",
        },
      ],
    })).find((tool) => tool.name === "praefectus_capabilities")!;
    const output = await capabilities.execute("call-1", {} as never);
    expect(output.details).toEqual({ error: { code: "praefectus_error" } });
  });

  test("rejects malformed or secret-bearing capability metadata", async () => {
    const base = windowsCapabilities();
    const { backend: _, ...missingBackend } = base;
    for (const childOutput of [
      { ...base, platform: "secret-platform" },
      { ...base, backend: "credential-backend" },
      { ...base, display_geometry_hash: "not-a-hash" },
      { ...base, display_geometry_hash: "A".repeat(64) },
      { ...base, permissions: { ...base.permissions, token_secret: true } },
      { ...base, detail: "backend secret" },
      {
        ...base,
        supported_actions: ["invoke", "set_value", "scroll", "click", "invoke"],
      },
      {
        ...base,
        action_capabilities: [
          ...base.action_capabilities,
          ...base.action_capabilities.slice(0, 2),
        ],
      },
      {
        ...base,
        action_capabilities: [
          {
            action: "credential_backend",
            delivery_route: "target_addressed",
            background_support: "guarded",
          },
        ],
        supported_actions: ["credential_backend"],
      },
      missingBackend,
    ]) {
      const capabilities = tools({}, async () => childOutput).find(
        (tool) => tool.name === "praefectus_capabilities",
      )!;
      const output = await capabilities.execute("call-1", {} as never);
      expect(output.details).toEqual({ error: { code: "praefectus_error" } });
      expect(JSON.stringify(output.details)).not.toContain("secret");
      expect(JSON.stringify(output.details)).not.toContain("credential");
    }
  });

  test("accepts exact CDP facts while hiding unsupported scroll execution", async () => {
    const capabilities = tools({}, async () => cdpCapabilities()).find(
      (tool) => tool.name === "praefectus_capabilities",
    )!;
    const output = await capabilities.execute("call-1", {} as never);
    expect(output.details).toEqual({
      ...cdpCapabilities(),
      supported_actions: ["invoke", "set_value"],
      action_capabilities: [
        cdpCapabilities().action_capabilities[0],
        cdpCapabilities().action_capabilities[2],
      ],
    });
  });

  test("rejects obsolete CDP click and pointer facts", async () => {
    const capabilities = tools({}, async () => ({
      ...cdpCapabilities(),
      supported_actions: ["click"],
      action_capabilities: [
        {
          action: "click",
          delivery_route: "pointer",
          background_support: "host_isolated_only",
        },
      ],
    })).find((tool) => tool.name === "praefectus_capabilities")!;
    const output = await capabilities.execute("call-1", {} as never);
    expect(output.details).toEqual({ error: { code: "praefectus_error" } });
  });

  test("accepts the bounded capability shapes for every runtime", async () => {
    for (const childOutput of [
      {
        platform: "macos",
        backend: "praefectus-macos-ax",
        supported_actions: [],
        action_capabilities: [],
        permissions: {
          accessibility: false,
          coordinate_capture: false,
          private_state: true,
          screen_recording: false,
        },
        display_geometry_hash: "0".repeat(64),
      },
      {
        platform: "linux",
        backend: "praefectus-atspi2",
        supported_actions: [],
        action_capabilities: [],
        permissions: {
          accessibility: false,
          atspi2: false,
          coordinate_capture: false,
          display_geometry: false,
          private_state: false,
          screen_recording: false,
        },
        display_geometry_hash: "0".repeat(64),
      },
      cdpCapabilities(),
    ]) {
      const capabilities = tools({}, async () => childOutput).find(
        (tool) => tool.name === "praefectus_capabilities",
      )!;
      const output = await capabilities.execute("call-1", {} as never);
      expect(output.details).not.toHaveProperty("error");
    }
  });

  test("rejects malformed or mismatched execute acknowledgements as nonretryable", async () => {
    const acceptedOnly = {
      acknowledgements: [
        {
          protocol_version: 2,
          operation_id: "operation-1",
          sequence: 0,
          action_hash: actionHash,
          replayed: false,
          state: { kind: "accepted" },
        },
      ],
    };
    const mixedHashes = outcomeUnknown();
    mixedHashes.acknowledgements.unshift({
      protocol_version: 2,
      operation_id: "operation-1",
      sequence: 0,
      action_hash: "b".repeat(64),
      replayed: false,
      state: { kind: "accepted" },
    } as never);
    const staleAcknowledgement = outcomeUnknown();
    staleAcknowledgement.acknowledgements[0].protocol_version = 1;
    const staleReceipt = outcomeUnknown();
    staleReceipt.acknowledgements[0].state.terminal.receipt.protocol_version = 1;
    const missingDeliveryRoute = outcomeUnknown();
    delete (
      missingDeliveryRoute.acknowledgements[0].state.terminal.receipt as {
        delivery_route?: string;
      }
    ).delivery_route;
    const mismatchedInteractionMode = outcomeUnknown();
    mismatchedInteractionMode.acknowledgements[0].state.terminal.receipt.interaction_mode =
      "background_only";
    const invalidContextPreservation = outcomeUnknown();
    invalidContextPreservation.acknowledgements[0].state.terminal.receipt.context_preservation =
      "host_isolated";
    const contradictoryUnknown = outcomeUnknown();
    contradictoryUnknown.acknowledgements[0].state.terminal.receipt.effect =
      "executed_unverified";
    const inconsistentRecoverySuccess = legacyRecovery();
    const recoveryTerminal =
      inconsistentRecoverySuccess.acknowledgements[0].state.terminal;
    recoveryTerminal.kind = "succeeded";
    recoveryTerminal.receipt.effect = "executed_unverified";
    delete (recoveryTerminal as { message?: string }).message;
    for (const childOutput of [
      {
        acknowledgements: [
          {
            state: {
              kind: "terminal",
              terminal: { kind: "succeeded", receipt: {} },
            },
          },
        ],
      },
      outcomeUnknown("another-operation"),
      acceptedOnly,
      mixedHashes,
      staleAcknowledgement,
      staleReceipt,
      missingDeliveryRoute,
      mismatchedInteractionMode,
      invalidContextPreservation,
      contradictoryUnknown,
      inconsistentRecoverySuccess,
    ]) {
      const execute = tools(
        {},
        async () => ({}),
        async () => childOutput,
      ).find((tool) => tool.name === "praefectus_execute")!;
      const output = await execute.execute("call-1", invokeRequest());
      expect(output.details).toEqual({
        error: { code: "praefectus_error" },
        retry_safe: false,
      });
    }
  });

  test("rejects mismatched verification before the host", async () => {
    const calls: unknown[] = [];
    const execute = tools(
      {},
      async () => ({}),
      async (request) => {
        calls.push(request);
        return outcomeUnknown();
      },
    ).find((tool) => tool.name === "praefectus_execute")!;
    const output = await execute.execute("call-1", {
      ...invokeRequest(),
      verification: {
        kind: "target_value_hash",
        sha256: "a".repeat(64),
      },
    } as never);
    expect(output.details).toEqual({
      error: { code: "invalid_request" },
      retry_safe: false,
    });
    expect(calls).toEqual([]);
  });

  test("accepts verified set_value with target_value_hash", async () => {
    const childOutput = outcomeUnknown();
    const terminal = childOutput.acknowledgements[0].state.terminal;
    terminal.kind = "succeeded";
    terminal.receipt.action_name = "set_value";
    terminal.receipt.effect = "verified";
    delete (terminal as { message?: string }).message;
    const execute = tools(
      {},
      async () => ({}),
      async () => childOutput,
    ).find((tool) => tool.name === "praefectus_execute")!;
    const output = await execute.execute("call-1", setValueRequest());
    expect(output.details).not.toHaveProperty("error");
    expect(JSON.stringify(output.details)).not.toContain("secret");
  });

  test("passes background-only intent without accepting host isolation", async () => {
    const childOutput = outcomeUnknown();
    const receipt = childOutput.acknowledgements[0].state.terminal.receipt;
    receipt.interaction_mode = "background_only";
    receipt.context_preservation = "unchanged_at_boundaries";
    const calls: unknown[] = [];
    const execute = tools(
      {},
      async () => ({}),
      async (request) => {
        calls.push(request);
        return childOutput;
      },
    ).find((tool) => tool.name === "praefectus_execute")!;
    const request = {
      ...invokeRequest(),
      interaction_mode: "background_only" as const,
    };
    const output = await execute.execute("call-1", request);
    expect(output.details).not.toHaveProperty("error");
    expect(calls).toEqual([request]);
    expect(JSON.stringify(output.details)).toContain("background_only");
    expect(JSON.stringify(output.details)).not.toContain("element_id");
  });

  test("accepts only nonretryable unknown facts for legacy torn claims", async () => {
    const recovery = legacyRecovery();
    const registered = tools(
      {},
      async () => recovery,
      async () => recovery,
    );
    const execute = registered.find(
      (tool) => tool.name === "praefectus_execute",
    )!;
    const status = registered.find(
      (tool) => tool.name === "praefectus_status",
    )!;
    for (const output of [
      await execute.execute("call-1", invokeRequest()),
      await status.execute("call-2", { operation_id: "operation-1" }),
    ]) {
      expect(output.details).not.toHaveProperty("error");
      expect(output.details).toHaveProperty("retry_safe", false);
      expect(JSON.stringify(output.details)).toContain(
        '"delivery_route":"unknown"',
      );
      expect(JSON.stringify(output.details)).toContain(
        '"interaction_mode":"unknown"',
      );
    }
  });

  test("accepts a set_value at the UTF-8 byte limit", async () => {
    const childOutput = outcomeUnknown();
    const terminal = childOutput.acknowledgements[0].state.terminal;
    terminal.kind = "succeeded";
    terminal.receipt.action_name = "set_value";
    terminal.receipt.effect = "verified";
    delete (terminal as { message?: string }).message;
    const calls: unknown[] = [];
    const execute = tools(
      {},
      async () => ({}),
      async (request) => {
        calls.push(request);
        return childOutput;
      },
    ).find((tool) => tool.name === "praefectus_execute")!;
    const request = setValueRequest("é".repeat(8192));
    const output = await execute.execute("call-1", request);
    expect(calls).toEqual([request]);
    expect(output.details).not.toHaveProperty("error");
  });

  test("returns a stable error when no host executor is configured", async () => {
    const registered = tools({}, async () => ({ ok: true }));
    const execute = registered.find(
      (tool) => tool.name === "praefectus_execute",
    )!;
    const output = await execute.execute("call-1", invokeRequest());
    expect(output.details).toEqual({
      error: { code: "host_executor_unavailable" },
      retry_safe: false,
    });
  });

  test("returns redacted stable errors for unavailable CLI operations", async () => {
    const registered = tools({}, async () => {
      throw new Error("backend secret");
    });
    const capabilities = registered.find(
      (tool) => tool.name === "praefectus_capabilities",
    )!;
    const status = registered.find(
      (tool) => tool.name === "praefectus_status",
    )!;
    await expect(
      capabilities.execute("call-1", {} as never),
    ).resolves.toMatchObject({
      details: { error: { code: "praefectus_unavailable" } },
    });
    await expect(
      status.execute("call-2", { operation_id: "operation-1" }),
    ).resolves.toMatchObject({
      details: { error: { code: "praefectus_unavailable" } },
    });
  });

  test("enforces the core request bounds in the tool schema", () => {
    const execute = tools({}).find(
      (tool) => tool.name === "praefectus_execute",
    )!;
    const request = invokeRequest();
    expect(Value.Check(execute.parameters, request)).toBeTrue();
    expect(
      Value.Check(execute.parameters, {
        ...request,
        interaction_mode: "background_only",
      }),
    ).toBeTrue();
    const { interaction_mode: _, ...withoutInteractionMode } = request;
    expect(Value.Check(execute.parameters, withoutInteractionMode)).toBeFalse();
    expect(
      Value.Check(execute.parameters, {
        ...request,
        session_isolation: "host_isolated",
      }),
    ).toBeFalse();
    expect(
      Value.Check(execute.parameters, {
        ...request,
        deadline_at_ms: Number.MAX_SAFE_INTEGER,
      }),
    ).toBeTrue();
    expect(
      Value.Check(execute.parameters, {
        ...request,
        deadline_at_ms: Number.MAX_SAFE_INTEGER + 1,
      }),
    ).toBeFalse();
    expect(
      Value.Check(execute.parameters, {
        ...request,
        ...setValueRequest(),
      }),
    ).toBeTrue();
    expect(
      Value.Check(execute.parameters, {
        ...request,
        verification: {
          kind: "target_value_hash",
          sha256: "a".repeat(64),
        },
      }),
    ).toBeFalse();
    expect(
      Value.Check(execute.parameters, {
        ...setValueRequest(),
        verification: { kind: "none" },
      }),
    ).toBeFalse();
    expect(
      Value.Check(execute.parameters, {
        ...request,
        verification: {
          kind: "target_value_hash",
          sha256: "A".repeat(64),
        },
      }),
    ).toBeFalse();
    expect(
      Value.Check(execute.parameters, {
        ...request,
        verification: {
          kind: "target_value_hash",
          sha256: "a".repeat(64),
          expected: "legacy",
        },
      }),
    ).toBeFalse();
    expect(
      Value.Check(execute.parameters, {
        ...request,
        operation_id: "contains spaces",
      }),
    ).toBeFalse();
    expect(
      Value.Check(execute.parameters, {
        ...request,
        verification_version: 1,
      }),
    ).toBeFalse();
    expect(
      Value.Check(execute.parameters, {
        ...request,
        action: { ...request.action, count: 2 },
      }),
    ).toBeFalse();
    expect(
      Value.Check(execute.parameters, {
        ...request,
        target: {
          ...request.target,
          target: {
            ...request.target.target,
            generation: 0,
          },
        },
      }),
    ).toBeFalse();
    expect(
      Value.Check(execute.parameters, {
        ...request,
        target: {
          ...request.target,
          target: {
            ...request.target.target,
            element_id: "A".repeat(64),
          },
        },
      }),
    ).toBeFalse();
    expect(
      Value.Check(execute.parameters, {
        ...request,
        target: { ...request.target, selector: "legacy" },
      }),
    ).toBeFalse();
    expect(
      Value.Check(execute.parameters, {
        ...request,
        target: {
          kind: "coordinates",
          x: 1,
          y: 2,
          display_id: "main",
          display_geometry_hash: "a".repeat(64),
          snapshot_id: "snapshot-1",
          snapshot_content_hash: "b".repeat(64),
        },
      }),
    ).toBeFalse();
  });

  test("redacts malformed error codes from child processes", async () => {
    const registered = tools({}, async () => ({
      ok: false,
      error: { code: "backend secret", message: "credential" },
    }));
    const capabilities = registered.find(
      (tool) => tool.name === "praefectus_capabilities",
    )!;
    const output = await capabilities.execute("call-1", {} as never);
    expect(output.details).toEqual({
      ok: false,
      error: { code: "praefectus_error" },
    });
  });

  test("writes one request envelope to the configured host executor", async () => {
    const bridge =
      'let input="";process.stdin.on("data",chunk=>input+=chunk);process.stdin.on("end",()=>process.stdout.write(input));';
    await expect(
      runHostExecutor(
        { operation_id: "op-1" },
        { hostExecutorCommand: [process.execPath, "-e", bridge] },
      ),
    ).resolves.toEqual({
      operation: "execute",
      request: { operation_id: "op-1" },
    });
  });

  test("rejects oversized host executor output", async () => {
    await expect(
      runHostExecutor(
        { operation_id: "op-1" },
        {
          hostExecutorCommand: [
            process.execPath,
            "-e",
            'process.stdout.write("x".repeat(1048577))',
          ],
        },
      ),
    ).rejects.toThrow("host executor failed");
  });

  test("rejects oversized host input before spawning", async () => {
    await expect(
      runHostExecutor(
        { value: "x".repeat(1048576) },
        { hostExecutorCommand: [process.execPath, "-e", "process.exit(0)"] },
      ),
    ).rejects.toThrow("host executor input exceeded limit");
  });

  test("handles a host executor that closes stdin early", async () => {
    await expect(
      runHostExecutor(
        { value: "x".repeat(65536) },
        { hostExecutorCommand: [process.execPath, "-e", "process.exit(1)"] },
      ),
    ).rejects.toThrow("host executor failed");
  });
});
