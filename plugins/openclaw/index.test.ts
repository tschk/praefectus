import { describe, expect, test } from "bun:test";
import { Value } from "typebox/value";
import { runHostExecutor } from "./cli.ts";
import { praefectusPlugin, tools } from "./index.ts";

describe("Praefectus OpenClaw tools", () => {
  test("passes only the action request to the host executor", async () => {
    const calls: unknown[][] = [];
    const run = async (...args: unknown[]) => {
      calls.push(args);
      return { acknowledgements: [{ state: { kind: "outcome_unknown" } }] };
    };
    const hostExecutor = async (...args: unknown[]) => {
      calls.push(args);
      return { acknowledgements: [{ state: { kind: "outcome_unknown" } }] };
    };
    const registered = tools({}, run as never, hostExecutor as never);
    const execute = registered.find(
      (tool) => tool.name === "praefectus_execute",
    )!;
    const request = {
      operation_id: "operation-1",
      authority_ref: "model-controlled-authority",
      signed_authority: "model-controlled-signature",
    };
    const output = await execute.execute("call-1", request);
    expect(calls).toEqual([[{ operation_id: "operation-1" }]]);
    expect(output.details).toEqual({
      acknowledgements: [
        { state: { kind: "outcome_unknown", retry_safe: false } },
      ],
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
        properties: { target: { anyOf: unknown[] } };
      }
    ).properties.target.anyOf[1] as {
      properties: {
        element_fingerprint: { properties: Record<string, unknown> };
      };
    };
    expect(
      Object.keys(element.properties.element_fingerprint.properties),
    ).toContain("process_id");
  });

  test("redacts action payloads if a backend ever echoes them", async () => {
    const registered = tools({}, async () => ({
      text: "typed secret",
      ok: true,
    }));
    const capabilities = registered.find(
      (tool) => tool.name === "praefectus_capabilities",
    )!;
    const output = await capabilities.execute("call-1", {} as never);
    expect(output.details).toEqual({ text: "[REDACTED]", ok: true });
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
        kind: "coordinates",
        x: 1,
        y: 2,
        display_id: "main",
        display_geometry_hash: "a".repeat(64),
        snapshot_id: "backend:snapshot/1",
        snapshot_content_hash: "b".repeat(64),
      },
      deadline_at_ms: 1,
      verification: { kind: "snapshot_changed" },
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
        action: { ...request.action, count: 4 },
      }),
    ).toBeFalse();
    expect(
      Value.Check(execute.parameters, {
        ...request,
        target: { ...request.target, snapshot_content_hash: "not-a-hash" },
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
});
