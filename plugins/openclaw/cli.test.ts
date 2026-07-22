import { expect, test } from "bun:test";
import { runHostExecutor } from "./cli.ts";

function isRunning(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

test("settles after the direct child exits with an inherited pipe open", async () => {
  const lifetime = process.platform === "win32" ? 250 : 10_000;
  const bridge = `
    const { spawn } = require("node:child_process");
    process.stdin.resume();
    process.stdin.on("end", () => {
      const descendant = spawn(process.execPath, ["-e", "setTimeout(() => {}, ${lifetime})"], {
        stdio: ["ignore", "inherit", "ignore"],
      });
      descendant.unref();
      process.stdout.write(JSON.stringify({ pid: descendant.pid }));
    });
  `;
  let pid = 0;
  try {
    const started = performance.now();
    const result = await runHostExecutor(
      { operation_id: "op-1" },
      { hostExecutorCommand: [process.execPath, "-e", bridge] },
    );
    expect(performance.now() - started).toBeLessThan(1_000);
    pid = (result as { pid: number }).pid;
    const deadline = Date.now() + 1_000;
    while (isRunning(pid) && Date.now() < deadline) await Bun.sleep(10);
    expect(isRunning(pid)).toBeFalse();
  } finally {
    if (pid && isRunning(pid)) {
      try {
        process.kill(pid, "SIGKILL");
      } catch {}
    }
  }
});
