// SPDX-License-Identifier: Apache-2.0
/**
 * The action guard's entry script: Claude Code runs this for every Bash,
 * PowerShell, Monitor and MCP call (hooks.json). It reads the hook input on stdin, hands it to `run` in
 * guard-lib.mjs, and prints the decision.
 * Design: docs/superpowers/specs/2026-10-21-action-guard-design.md §4.
 *
 * Three outcomes:
 *   - prints nothing and exits 0: the call is not guarded, Claude Code's normal
 *     permission flow continues. No network is touched.
 *   - prints one JSON decision and exits 0: allow (with the reviewer's edits
 *     when there are any) or deny.
 *   - exits 1 with nothing on stdout: the input was not a hook call, or the
 *     script itself failed. The hook is set to `onFailure: "block"`, so that
 *     stops the call.
 *
 * This file is thin on purpose, and it always runs `main`. It used to decide
 * whether it was the entry point by comparing argv[1] with its own path, and a
 * mismatch made it exit 0 having done nothing, which passes every call. All the
 * logic lives in guard-lib.mjs, which has no entry point and is the file the
 * unit tests import.
 *
 * This is a seatbelt against an agent's honest mistakes, not a security
 * boundary. No dependencies: Node 18 built-ins and global fetch.
 */
import { currentBranch, run } from "./guard-lib.mjs";

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

async function main() {
  try {
    const input = JSON.parse(await readStdin());
    const output = await run(input, process.env, {
      fetch: globalThis.fetch,
      currentBranch,
      sleep: ms => new Promise(resolve => setTimeout(resolve, ms)),
      now: () => Date.now(),
    });
    // Exit from the write callback: an open connection must not keep the process
    // alive past its decision, and an exit before the flush would cut the output.
    if (output === null) process.exit(0);
    // A decision that was not written is a crash: exit 1 blocks the call.
    process.stdout.write(JSON.stringify(output), err => process.exit(err ? 1 : 0));
  } catch (error) {
    // A crash prints no decision. The error's text is left out: it can quote the
    // hook input, which can hold a secret.
    process.stderr.write(
      `The LightRest action guard failed (${error?.name ?? "error"}), so the call was blocked.\n`
    );
    process.exit(1);
  }
}

await main();
