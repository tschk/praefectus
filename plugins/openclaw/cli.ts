import { spawn } from "node:child_process";

const MAX_OUTPUT_BYTES = 1024 * 1024;

export type PraefectusOptions = {
  command?: string;
  ledger?: string;
  hostExecutorCommand?: readonly string[];
};

export type PraefectusCommand = "capabilities" | "status";

export type HostExecutor = (request: unknown) => Promise<unknown>;

export async function runPraefectus(
  operation: PraefectusCommand,
  input: unknown,
  options: PraefectusOptions = {},
): Promise<unknown> {
  const args: string[] = [operation];
  if (options.ledger) args.push("--ledger", options.ledger);
  if (operation === "status") args.push(String(input));
  return new Promise((resolve, reject) => {
    const child = spawn(options.command ?? "praefectus", args, {
      stdio: ["pipe", "pipe", "ignore"],
      windowsHide: true,
    });
    const stdout: Buffer[] = [];
    let outputBytes = 0;
    const timeout = setTimeout(() => child.kill(), 30_000);
    child.stdout.on("data", (chunk: Buffer) => {
      outputBytes += chunk.length;
      if (outputBytes <= MAX_OUTPUT_BYTES) stdout.push(chunk);
      else child.kill();
    });
    child.on("error", () => {
      clearTimeout(timeout);
      reject(new Error("praefectus command failed"));
    });
    child.on("close", (code) => {
      clearTimeout(timeout);
      if (outputBytes > MAX_OUTPUT_BYTES) {
        reject(new Error("praefectus output exceeded limit"));
        return;
      }
      const output = Buffer.concat(stdout).toString("utf8");
      let value: unknown;
      try {
        value = JSON.parse(output);
      } catch {
        reject(new Error("praefectus returned invalid JSON"));
        return;
      }
      if (code === 0) resolve(value);
      else reject(new Error("praefectus command failed"));
    });
    child.stdin.end();
  });
}

export async function runHostExecutor(
  request: unknown,
  options: PraefectusOptions,
): Promise<unknown> {
  const command = options.hostExecutorCommand;
  if (!command?.length) throw new Error("host executor is not configured");
  const [file, ...args] = command;
  if (!file) throw new Error("host executor is not configured");
  const input = Buffer.from(JSON.stringify({ operation: "execute", request }));
  if (input.length > MAX_OUTPUT_BYTES)
    throw new Error("host executor input exceeded limit");
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, {
      stdio: ["pipe", "pipe", "ignore"],
      windowsHide: true,
    });
    const stdout: Buffer[] = [];
    let outputBytes = 0;
    const timeout = setTimeout(() => child.kill(), 30_000);
    child.stdout.on("data", (chunk: Buffer) => {
      outputBytes += chunk.length;
      if (outputBytes <= MAX_OUTPUT_BYTES) stdout.push(chunk);
      else child.kill();
    });
    child.on("error", () => {
      clearTimeout(timeout);
      reject(new Error("host executor failed"));
    });
    child.stdin.on("error", () => {
      clearTimeout(timeout);
      child.kill();
      reject(new Error("host executor failed"));
    });
    child.on("close", (code) => {
      clearTimeout(timeout);
      if (code !== 0 || outputBytes > MAX_OUTPUT_BYTES) {
        reject(new Error("host executor failed"));
        return;
      }
      try {
        resolve(JSON.parse(Buffer.concat(stdout).toString("utf8")));
      } catch {
        reject(new Error("host executor returned invalid JSON"));
      }
    });
    child.stdin.end(input);
  });
}
