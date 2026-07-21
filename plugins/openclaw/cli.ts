import { spawn } from "node:child_process";

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
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    const timeout = setTimeout(() => child.kill(), 30_000);
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.on("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.on("close", (code) => {
      clearTimeout(timeout);
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
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, {
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    const stdout: Buffer[] = [];
    const timeout = setTimeout(() => child.kill(), 30_000);
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.on("error", () => {
      clearTimeout(timeout);
      reject(new Error("host executor failed"));
    });
    child.on("close", (code) => {
      clearTimeout(timeout);
      if (code !== 0) {
        reject(new Error("host executor failed"));
        return;
      }
      try {
        resolve(JSON.parse(Buffer.concat(stdout).toString("utf8")));
      } catch {
        reject(new Error("host executor returned invalid JSON"));
      }
    });
    child.stdin.end(JSON.stringify({ operation: "execute", request }));
  });
}
