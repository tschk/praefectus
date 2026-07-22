import { spawn } from "node:child_process";

const MAX_OUTPUT_BYTES = 1024 * 1024;
const COMMAND_TIMEOUT_MS = 30_000;
const EXIT_DRAIN_TIMEOUT_MS = 100;

export type PraefectusOptions = {
  command?: string;
  ledger?: string;
  hostExecutorCommand?: readonly string[];
};

export type PraefectusCommand = "capabilities" | "status";

export type HostExecutor = (request: unknown) => Promise<unknown>;

function runCommand(
  file: string,
  args: readonly string[],
  input: Buffer | undefined,
  failedMessage: string,
  outputLimitMessage: string,
): Promise<{ code: number | null; output: Buffer }> {
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, {
      detached: process.platform !== "win32",
      stdio: ["pipe", "pipe", "ignore"],
      windowsHide: true,
    });
    const stdout: Buffer[] = [];
    let outputBytes = 0;
    let exited = false;
    let exitCode: number | null = null;
    let stdoutEnded = false;
    let settled = false;
    let stopped = false;
    let drainTimeout: ReturnType<typeof setTimeout> | undefined;

    const stop = () => {
      if (stopped) return;
      stopped = true;
      if (process.platform !== "win32" && child.pid !== undefined) {
        try {
          process.kill(-child.pid, "SIGKILL");
          return;
        } catch {}
      }
      try {
        child.kill("SIGKILL");
      } catch {}
    };
    const timeout = setTimeout(
      () => finish(new Error(failedMessage)),
      COMMAND_TIMEOUT_MS,
    );
    const cleanup = () => {
      clearTimeout(timeout);
      if (drainTimeout !== undefined) clearTimeout(drainTimeout);
      stop();
      child.removeAllListeners();
      child.stdin.removeAllListeners();
      child.stdout.removeAllListeners();
      child.stdin.destroy();
      child.stdout.destroy();
    };
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (error) reject(error);
      else resolve({ code: exitCode, output: Buffer.concat(stdout) });
    };
    const finishExit = () => {
      if (exited && stdoutEnded) finish();
    };

    child.stdout.on("data", (chunk: Buffer) => {
      outputBytes += chunk.length;
      if (outputBytes <= MAX_OUTPUT_BYTES) stdout.push(chunk);
      else finish(new Error(outputLimitMessage));
    });
    child.stdout.on("end", () => {
      stdoutEnded = true;
      finishExit();
    });
    child.on("error", () => finish(new Error(failedMessage)));
    child.stdin.on("error", () => finish(new Error(failedMessage)));
    child.on("exit", (code) => {
      exited = true;
      exitCode = code;
      stop();
      if (stdoutEnded) finish();
      else drainTimeout = setTimeout(() => finish(), EXIT_DRAIN_TIMEOUT_MS);
    });
    child.stdin.end(input);
  });
}

export async function runPraefectus(
  operation: PraefectusCommand,
  input: unknown,
  options: PraefectusOptions = {},
): Promise<unknown> {
  const args: string[] = [operation];
  if (options.ledger) args.push("--ledger", options.ledger);
  if (operation === "status") args.push(String(input));
  const { code, output } = await runCommand(
    options.command ?? "praefectus",
    args,
    undefined,
    "praefectus command failed",
    "praefectus output exceeded limit",
  );
  let value: unknown;
  try {
    value = JSON.parse(output.toString("utf8"));
  } catch {
    throw new Error("praefectus returned invalid JSON");
  }
  if (code === 0) return value;
  throw new Error("praefectus command failed");
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
  const result = await runCommand(
    file,
    args,
    input,
    "host executor failed",
    "host executor failed",
  );
  if (result.code !== 0) throw new Error("host executor failed");
  try {
    return JSON.parse(result.output.toString("utf8"));
  } catch {
    throw new Error("host executor returned invalid JSON");
  }
}
