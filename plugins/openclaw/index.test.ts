import { describe, expect, test } from "bun:test";
import { Value } from "typebox/value";
import { runHostExecutor } from "./cli.ts";
import { praefectusPlugin, tools } from "./index.ts";

const actionHash = "a".repeat(64);

function outcomeUnknown(operationId = "operation-1") {
  return {
    acknowledgements: [
      {
        protocol_version: 1,
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
              protocol_version: 1,
              action_name: "click",
              action_hash: actionHash,
              started_at_ms: 1,
              finished_at_ms: 2,
              backend: "test",
              fallback_chain: [],
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
    const request = {
      operation_id: "operation-1",
      action: { kind: "click" },
      verification: { kind: "none" },
      verification_version: 1,
      authority_ref: "model-controlled-authority",
      signed_authority: "model-controlled-signature",
    };
    const output = await execute.execute("call-1", request);
    expect(calls).toEqual([
      [
        {
          operation_id: "operation-1",
          action: { kind: "click" },
          verification: { kind: "none" },
          verification_version: 1,
        },
      ],
    ]);
    expect(output.details).toEqual({
      acknowledgements: [
        {
          protocol_version: 1,
          operation_id: "operation-1",
          sequence: 2,
          action_hash: actionHash,
          replayed: false,
          state: "terminal",
          terminal: {
            kind: "outcome_unknown",
            receipt: {
              protocol_version: 1,
              action_name: "click",
              action_hash: actionHash,
              started_at_ms: 1,
              finished_at_ms: 2,
              backend: "test",
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

  test("requires the core process and window target fence", () => {
    const execute = tools({}).find(
      (tool) => tool.name === "praefectus_execute",
    )!;
    const element = (
      execute.parameters as unknown as {
        properties: { target: unknown };
      }
    ).properties.target as {
      properties: {
        element_fingerprint: { properties: Record<string, unknown> };
      };
    };
    expect(
      Object.keys(element.properties.element_fingerprint.properties),
    ).toContain("process_id");
  });

  test("rejects arbitrary child output without echoing it", async () => {
    const childOutputs: unknown[] = [
      "backend secret",
      ["backend secret"],
      {
        text: "typed secret",
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

  test("rejects malformed or mismatched execute acknowledgements as nonretryable", async () => {
    const acceptedOnly = {
      acknowledgements: [
        {
          protocol_version: 1,
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
      protocol_version: 1,
      operation_id: "operation-1",
      sequence: 0,
      action_hash: "b".repeat(64),
      replayed: false,
      state: { kind: "accepted" },
    } as never);
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
    ]) {
      const execute = tools(
        {},
        async () => ({}),
        async () => childOutput,
      ).find((tool) => tool.name === "praefectus_execute")!;
      const output = await execute.execute("call-1", {
        operation_id: "operation-1",
        action: { kind: "click" },
        verification: { kind: "none" },
      } as never);
      expect(output.details).toEqual({
        error: { code: "praefectus_error" },
        retry_safe: false,
      });
    }
  });

  test("rejects unverified success when target verification was requested", async () => {
    const childOutput = outcomeUnknown();
    const terminal = childOutput.acknowledgements[0].state.terminal;
    terminal.kind = "succeeded";
    terminal.receipt.effect = "executed_unverified";
    delete (terminal as { message?: string }).message;
    const execute = tools(
      {},
      async () => ({}),
      async () => childOutput,
    ).find((tool) => tool.name === "praefectus_execute")!;
    const output = await execute.execute("call-1", {
      operation_id: "operation-1",
      action: { kind: "click" },
      verification: { kind: "target_state" },
    } as never);
    expect(output.details).toEqual({
      error: { code: "praefectus_error" },
      retry_safe: false,
    });
  });

  test("returns a stable error when no host executor is configured", async () => {
    const registered = tools({}, async () => ({ ok: true }));
    const execute = registered.find(
      (tool) => tool.name === "praefectus_execute",
    )!;
    const output = await execute.execute("call-1", {} as never);
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
    const request = {
      operation_id: "operation-1",
      action: {
        kind: "click",
        button: "left",
        count: 1,
        allow_coordinate_fallback: false,
      },
      target: {
        kind: "element",
        selector: "selector",
        snapshot_id: "backend:snapshot/1",
        element_fingerprint: {
          backend: "backend",
          id: "element-1",
          app: "app",
          process_id: 1,
          window: "window",
          role: "button",
          label: "Submit",
          bounds: { x: 1, y: 2, width: 3, height: 4 },
        },
      },
      deadline_at_ms: 1,
      verification: { kind: "snapshot_changed" },
      verification_version: 1,
      safety: "reversible",
    };
    expect(Value.Check(execute.parameters, request)).toBeTrue();
    expect(
      Value.Check(execute.parameters, {
        ...request,
        operation_id: "contains spaces",
      }),
    ).toBeFalse();
    expect(
      Value.Check(execute.parameters, {
        ...request,
        verification_version: 2,
      }),
    ).toBeFalse();
    expect(
      Value.Check(execute.parameters, {
        ...request,
        action: { ...request.action, count: 4 },
      }),
    ).toBeFalse();
    expect(
      Value.Check(execute.parameters, {
        ...request,
        target: {
          ...request.target,
          element_fingerprint: {
            ...request.target.element_fingerprint,
            process_id: 0,
          },
        },
      }),
    ).toBeFalse();
    expect(
      Value.Check(execute.parameters, {
        ...request,
        target: {
          ...request.target,
          element_fingerprint: {
            ...request.target.element_fingerprint,
            label: "x".repeat(1025),
          },
        },
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
