// SPDX-License-Identifier: Apache-2.0
/**
 * The action guard's logic: a PreToolUse hook that holds a guarded production
 * call until a person has authorised it with their passkey.
 * Design: docs/superpowers/specs/2026-10-21-action-guard-design.md §4.
 *
 * guard.mjs is the entry point Claude Code runs (stdin in, decision out); it
 * calls `run` below. This file has no entry point, so importing it does nothing,
 * which is what the unit tests rely on. `run` returns the hook output, or null
 * for a call that is not guarded (Claude Code's normal permission flow then
 * continues and no network is touched). It throws for input that is not a hook
 * call; the entry turns that into exit 1, which `onFailure: "block"` makes a
 * block.
 *
 * Order for a guarded call: policy (policy.mjs) → secret check (secrets.mjs) →
 * endpoint check (LIGHTREST_MCP_URL must be https, or http on this machine) →
 * key → `request_action_review` → poll `get_review` → decision (decide.mjs).
 * A call that carries a secret, or that the policy refuses, is never sent.
 *
 * What is sent is the proposal: `{tool, arguments}`. For a shell tool (Bash,
 * PowerShell, Monitor) the arguments are the `command` alone, and an edited
 * command is put back into the whole input by decide (its `baseInput`). For any
 * other tool the arguments are the tool's whole input.
 *
 * Every failure after the policy is a deny that says what happened and what to
 * do next. Nothing is retried: a server that refused once will refuse again,
 * and the agent can call again once the cause is fixed.
 *
 * The idempotency key (`externalRef`) is `guard-` plus the first 32 hex of the
 * SHA-256 of the session id, a newline and the call's canonical JSON, so a
 * retry of the same call in the same session finds the same capture. The
 * server answers a reused ref with the existing capture even when it is dead,
 * so a capture that expired is asked for again under the next ref in a fixed
 * chain (ref, then the hash of ref and the expired capture's id, at most
 * MAX_HOPS times). A later retry walks the same chain to the live capture. A
 * capture a reviewer discarded is final.
 *
 * Test-only variables: LIGHTREST_MCP_URL (the endpoint), LIGHTREST_GUARD_POLL_MS
 * and LIGHTREST_GUARD_BUDGET_MS (the poll interval and the total wait).
 *
 * This is a seatbelt against an agent's honest mistakes, not a security
 * boundary. No dependencies: Node 18 built-ins and global fetch.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { decide, deny } from "./decide.mjs";
import canonicalize from "./jcs.mjs";
import { classify, SHELL_TOOLS } from "./policy.mjs";
import { findSecret } from "./secrets.mjs";

const ENDPOINT = "https://lightrest.net/mcp";
const PROTOCOL_VERSION = "2026-07-28";
const POLL_MS = 5_000;
const BUDGET_MS = 570_000;
const REQUEST_MAX_MS = 15_000;
/** How many times a call is asked for again after its capture expired. */
const MAX_HOPS = 3;
const AGENTS_URL = "https://lightrest.net/app/agents";
/** The most characters of a server's message shown to the agent. */
const MAX_QUOTED = 300;

const isObject = value =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const sha256Hex = text => createHash("sha256").update(text).digest("hex");

/** A positive whole number from an environment value, or the default. */
function millis(value, fallback) {
  const n = Number.parseInt(String(value ?? ""), 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

/** A server's own words, on one line and cut short, for a deny reason. */
function quote(text) {
  const one = String(text).replace(/\s+/g, " ").trim();
  return one.length > MAX_QUOTED ? `${one.slice(0, MAX_QUOTED)}...` : one;
}

/** The plugin's version, sent as the client version. */
function pluginVersion() {
  try {
    const file = new URL("../.claude-plugin/plugin.json", import.meta.url);
    const version = JSON.parse(readFileSync(file, "utf8")).version;
    return typeof version === "string" && version.length > 0 ? version : "0";
  } catch {
    return "0";
  }
}

/** A failure that ends the run with a deny. */
class Stop extends Error {
  constructor(reason) {
    super(reason);
    this.reason = reason;
  }
}

/**
 * One JSON-RPC `tools/call`. Returns the `result`. Throws Stop for every way it
 * can go wrong, so the caller has one place to turn a failure into a deny.
 */
async function callTool(name, args, ctx) {
  const left = ctx.deadline - ctx.io.now();
  if (left <= 0) throw new Stop(ctx.waiting());
  const limit = Math.min(REQUEST_MAX_MS, left);
  // Whether the end of the whole wait, rather than the 15 s cap, cuts this request off.
  const endsWithBudget = left <= REQUEST_MAX_MS;
  const meta = {
    "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
    "io.modelcontextprotocol/clientCapabilities": {},
    "io.modelcontextprotocol/clientInfo": {
      name: "lightrest-guard",
      version: ctx.version,
    },
  };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), limit);
  let response;
  let text;
  try {
    response = await ctx.io.fetch(ctx.url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${ctx.key}`,
        "mcp-method": "tools/call",
        "mcp-name": name,
        "mcp-protocol-version": PROTOCOL_VERSION,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: ++ctx.requests,
        method: "tools/call",
        params: { name, arguments: args, _meta: meta },
      }),
      // A redirect would send the agent key and the call somewhere else.
      redirect: "error",
      signal: controller.signal,
    });
    text = await response.text();
  } catch (error) {
    if (controller.signal.aborted) {
      // The wait is over: the same words as when the budget runs out between polls.
      if (endsWithBudget) throw new Stop(ctx.waiting());
      throw new Stop(
        `LightRest did not answer within ${REQUEST_MAX_MS / 1000} seconds (the request timed out), so nothing was run.${ctx.afterwards()}`
      );
    }
    const cause = error?.cause?.code ?? error?.code ?? error?.name ?? "error";
    throw new Stop(
      `The guard could not reach LightRest (${cause}), so nothing was run. Check the connection and call it again.${ctx.afterwards()}`
    );
  } finally {
    clearTimeout(timer);
  }

  if (response.status === 401) {
    throw new Stop(
      `LightRest refused the agent key (HTTP 401), so nothing was run. Check that ${"LIGHTREST_AGENT_KEY"} or the plugin's api_key option holds a current key from ${AGENTS_URL}.`
    );
  }
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = undefined;
  }
  if (isObject(body) && isObject(body.error)) {
    const code = typeof body.error.code === "number" ? ` (code ${body.error.code})` : "";
    const message =
      typeof body.error.message === "string" && body.error.message !== ""
        ? quote(body.error.message)
        : "no message";
    throw new Stop(
      `LightRest rejected the request: ${message}${code}. Nothing was run. ${adviceFor(body.error.code)}${ctx.afterwards()}`
    );
  }
  if (!response.ok) {
    const said =
      isObject(body) && typeof body.message === "string" && body.message !== ""
        ? `: ${quote(body.message)}`
        : "";
    const advice =
      response.status === 429
        ? adviceFor(RATE_LIMITED)
        : "Call it again once that is fixed.";
    throw new Stop(
      `LightRest answered HTTP ${response.status}${said}, so nothing was run. ${advice}${ctx.afterwards()}`
    );
  }
  if (!isObject(body) || !isObject(body.result)) {
    throw new Stop(unreadable("it had no result", ctx));
  }
  const result = body.result;
  if (result.isError === true) {
    const said = Array.isArray(result.content)
      ? result.content
          .map(part => (isObject(part) && typeof part.text === "string" ? part.text : ""))
          .filter(Boolean)
          .join(" ")
      : "";
    // Bad arguments (and canonical JSON over 64 KB) come back as a tool error
    // whose text starts "Invalid arguments"; changing the call is the fix for
    // those. Any other tool error is not the call's fault.
    const advice =
      /^Invalid arguments/.test(said) || /64\s?KB/i.test(said)
        ? CHANGE_THE_CALL
        : CALL_AGAIN;
    throw new Stop(
      `LightRest refused the request${said ? `: ${quote(said)}` : ""}. Nothing was run. ${advice}${ctx.afterwards()}`
    );
  }
  // The server's own clock, from the Date header; null when there is none or it is not a date.
  const date = response.headers?.get?.("date");
  const serverTime = typeof date === "string" ? Date.parse(date) : Number.NaN;
  return { result, serverTime: Number.isFinite(serverTime) ? serverTime : null };
}

/** JSON-RPC codes the /mcp route answers with (server/mcp/routes.ts). */
const INVALID_PARAMS = -32602;
const TERMS_NOT_ACCEPTED = -32001;
const RATE_LIMITED = -32000;

const CHANGE_THE_CALL = "Change the call so the request is accepted, then call it again.";
const CALL_AGAIN = "You can call it again; if it keeps failing, tell the person.";

/**
 * What the agent should do about a JSON-RPC error, by its code. The route sends
 * -32602 for a malformed request (an unknown tool, no _meta, no tool name, a
 * task that is not there): the plugin is out of step with the server, and
 * rephrasing the call does nothing. Bad arguments come back as a tool error,
 * not as a JSON-RPC error (see the isError branch in callTool). Telling the
 * agent to change a guarded call when the call is not at fault would push it to
 * rephrase it.
 */
function adviceFor(code) {
  switch (code) {
    case INVALID_PARAMS:
      return `${CALL_AGAIN} The LightRest plugin may need updating.`;
    case TERMS_NOT_ACCEPTED:
      return "Ask an owner of your organisation to accept the current Terms at lightrest.net, then call it again.";
    case RATE_LIMITED:
      return "Wait a minute, then call it again.";
    default:
      return CALL_AGAIN;
  }
}

function unreadable(what, ctx) {
  return `The guard cannot read LightRest's reply (${what}), so nothing was run. Call it again; if this repeats, tell the person.${ctx.afterwards()}`;
}

/** The `structuredContent` of a result, or a Stop. */
function structured(result, ctx) {
  if (!isObject(result.structuredContent)) {
    throw new Stop(unreadable("it had no structured content", ctx));
  }
  return result.structuredContent;
}

/**
 * How long a seal authorises the call (founder ruling): a seal older than this
 * is spent. It lets the agent run the call it was sealed for a short while after
 * the reviewer acted, and no later.
 *
 * The local clock is never the judge. A capture this run saw pending and then
 * sealed is fresh by construction: the seal came after the request. A capture
 * already sealed when first read is aged against the server's own time, the
 * Date header of that reply, so a local clock a day out in either direction
 * changes nothing; without a usable Date header the local clock is the best
 * reference left. In both cases a seal time more than SEAL_CLOCK_SLACK_MS after
 * the reference is the clocks disagreeing, and a deny: a seal cannot come from
 * the future.
 */
const SEAL_MAX_AGE_MINUTES = 15;
const SEAL_MAX_AGE_MS = SEAL_MAX_AGE_MINUTES * 60_000;
const SEAL_CLOCK_SLACK_MS = 60_000;
/** An ISO 8601 time with an explicit zone (what Date#toISOString writes). A time without one means the reader's own zone. */
const SEAL_TIME =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})$/;

/**
 * The seal time (`review.sealedAt` in the get_review reply) in ms, or null when
 * the reply does not say or says something that is not a time with a zone.
 * Hour 24 is refused: Date.parse reads it as the next midnight.
 */
function sealTime(sc) {
  const at = isObject(sc.review) ? sc.review.sealedAt : undefined;
  if (typeof at !== "string" || !SEAL_TIME.test(at) || at.includes("T24:")) {
    return null;
  }
  const sealed = Date.parse(at);
  return Number.isFinite(sealed) ? sealed : null;
}

/** Hosts an http endpoint may name. Anything else must be https. */
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]", "localhost"]);

/**
 * The endpoint to send to, or null when LIGHTREST_MCP_URL names one the guard
 * will not use. The call and the agent key go to this address, so it is https,
 * or http on this machine (the tests), and carries no credentials of its own.
 */
function endpointOf(value) {
  if (value === undefined || value === "") return ENDPOINT;
  let url;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.username !== "" || url.password !== "") return null;
  if (url.protocol === "https:") return value;
  if (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname)) return value;
  return null;
}

/**
 * The ref for the next hop: the hash of this ref and the expired capture's id.
 * A fixed function of both, so a retry walks the same chain.
 */
const nextRef = (ref, captureId) =>
  `guard-${sha256Hex(`${ref}\n${captureId}`).slice(0, 32)}`;

/**
 * @param {object} input the hook input: {session_id?, cwd?, hook_event_name, tool_name, tool_input}
 * @param {Record<string, string | undefined>} env
 * @param {{ fetch: typeof fetch, currentBranch: (cwd: string | undefined) => string | null, sleep: (ms: number) => Promise<void>, now: () => number }} io
 * @returns {Promise<object | null>} the hook output, or null to pass
 */
export async function run(input, env, io) {
  // Something that is not a hook call is a crash (exit 1, which blocks), never a
  // pass: a pass lets the call run unreviewed.
  if (
    !isObject(input) ||
    typeof input.tool_name !== "string" ||
    input.tool_name === ""
  ) {
    throw new TypeError("the hook input has no tool_name");
  }
  // Claude Code always sends an object. Checked before the policy, which reads
  // anything else as {} and so would pass a Bash call whose input is a string.
  if (!isObject(input.tool_input)) {
    throw new TypeError("the hook input's tool_input is not an object");
  }
  const toolName = input.tool_name;
  const toolInput = input.tool_input;
  const cwd = typeof input.cwd === "string" ? input.cwd : undefined;

  const verdict = classify(toolName, toolInput, {
    currentBranch: io.currentBranch,
    cwd,
  });
  if (verdict.action === "pass") return null;
  if (verdict.action === "refuse") return deny(verdict.reason);

  // What is sent, hashed into the ref and compared with the seal. For a shell
  // tool that is the command alone: description, timeout and run_in_background
  // say how the agent runs the command, not what it does, and a retry worded
  // differently must still find its seal. `baseInput` lets decide put an
  // edited command back into the whole input. Any other tool sends its input.
  const shell = SHELL_TOOLS.has(toolName);
  const args = shell ? { command: toolInput.command } : toolInput;
  const baseInput = shell ? toolInput : undefined;
  const secret = findSecret(args);
  if (secret !== null) {
    return deny(
      `This call carries a secret (${secret}); remove it and call again. ` +
        `Nothing was sent to LightRest. Read the value from an environment variable inside the command, or ask the person to set it in the provider's dashboard.`
    );
  }

  const url = endpointOf(env.LIGHTREST_MCP_URL);
  if (url === null) {
    return deny(
      `LIGHTREST_MCP_URL is set to something the guard will not send a call to, so nothing was run. ` +
        `It must be an https address, or an http address on localhost, 127.0.0.1 or [::1]. Unset it to use ${ENDPOINT}.`
    );
  }

  const key = env.CLAUDE_PLUGIN_OPTION_API_KEY || env.LIGHTREST_AGENT_KEY;
  if (!key) {
    return deny(
      `Set your LightRest agent key (the plugin's api_key option, or the LIGHTREST_AGENT_KEY environment variable), then call this again. ` +
        `Create a key at ${AGENTS_URL}. Nothing was run.`
    );
  }

  const proposed = { tool: toolName, arguments: args };
  // The spec's `session_id ?? ""`: null and absent are "", anything else its String().
  const session = `${input.session_id ?? ""}`;
  const hasSession = session !== "";
  let ref = `guard-${sha256Hex(`${session}\n${canonicalize(proposed)}`).slice(0, 32)}`;

  const started = io.now();
  const poll = millis(env.LIGHTREST_GUARD_POLL_MS, POLL_MS);
  const budget = millis(env.LIGHTREST_GUARD_BUDGET_MS, BUDGET_MS);
  let reviewUrl = null;
  const ctx = {
    io,
    key,
    url,
    version: pluginVersion(),
    deadline: started + budget,
    requests: 0,
    waiting: () =>
      reviewUrl === null
        ? `LightRest did not answer in time (the request timed out), so nothing was run. Call it again.`
        : `Waiting for authorisation at ${reviewUrl}. Call it again after it is sealed.`,
    afterwards: () =>
      reviewUrl === null
        ? ""
        : ` The review is at ${reviewUrl}; call it again after it is sealed.`,
  };

  try {
    // Expired captures and spent seals are counted apart, each up to MAX_HOPS.
    let expiredHops = 0;
    let spentHops = 0;
    for (;;) {
      reviewUrl = null;
      const reply = structured(
        (
          await callTool(
            "request_action_review",
            {
              tool: proposed.tool,
              arguments: proposed.arguments,
              aiSystem: { name: "Claude Code" },
              externalRef: ref,
              expiresInMinutes: 60,
            },
            ctx
          )
        ).result,
        ctx
      );
      if (
        typeof reply.captureId !== "string" ||
        typeof reply.reviewUrl !== "string" ||
        typeof reply.status !== "string"
      ) {
        throw new Stop(unreadable("it had no capture id, status or review link", ctx));
      }
      const captureId = reply.captureId;
      reviewUrl = reply.reviewUrl;

      let status = reply.status;
      let outcome = null;
      let spent = false;
      // Whether this run saw the capture unsealed: the request said pending, or a poll did.
      let sawPending = status === "pending";
      if (status === "expired" || status === "discarded") {
        outcome = decide(proposed, { status }, reviewUrl, { baseInput });
      } else {
        // A fresh capture cannot be sealed yet, so it waits before the first poll.
        let first = status !== "pending";
        for (;;) {
          if (!first) {
            const left = ctx.deadline - io.now();
            if (left <= 0) throw new Stop(ctx.waiting());
            await io.sleep(Math.min(poll, left));
          }
          first = false;
          const polled = await callTool("get_review", { captureId }, ctx);
          const sc = structured(polled.result, ctx);
          status = sc.status;
          if (status === "pending") sawPending = true;
          // An expired capture comes back from decide as a final deny; the hop
          // check below reads `status` and asks again instead of returning it.
          outcome = decide(proposed, sc, reviewUrl, { baseInput });
          if (outcome.final) {
            // Only an allow depends on how old the seal is: a rejection or any
            // other deny stands whatever its age.
            if (outcome.output.hookSpecificOutput.permissionDecision === "allow") {
              const sealed = sealTime(sc);
              const reference = polled.serverTime ?? io.now();
              if (sealed === null) {
                outcome = {
                  final: true,
                  output: deny(
                    `The review is sealed but its reply does not say when, so the guard cannot tell whether the authorisation is current and nothing was run. ` +
                      `Do not run it. Ask the person to check the review at ${reviewUrl}.`
                  ),
                };
              } else if (sealed > reference + SEAL_CLOCK_SLACK_MS) {
                outcome = {
                  final: true,
                  output: deny(
                    `The review says it was sealed after the time LightRest gave for its reply, so the clocks disagree and the guard cannot tell whether the authorisation is current. Nothing was run. ` +
                      `Do not run it. Ask the person to check the review at ${reviewUrl}.`
                  ),
                };
              } else if (!sawPending && reference - sealed > SEAL_MAX_AGE_MS) {
                spent = true;
              }
            }
            break;
          }
        }
      }

      const ask = hasSession ? "; a new Claude Code session asks again" : "";
      if (spent) {
        if (spentHops >= MAX_HOPS) {
          return deny(
            `Each of the ${spentHops + 1} authorisations sealed for this call was more than ${SEAL_MAX_AGE_MINUTES} minutes old when the guard read it, so it stopped asking and nothing was run. ` +
              `Do not run it. Ask the person whether they still want it${ask}. Latest review: ${reviewUrl}.`
          );
        }
        spentHops++;
        ref = nextRef(ref, captureId);
        continue;
      }
      if (status === "expired") {
        if (expiredHops >= MAX_HOPS) {
          return deny(
            `LightRest expired ${expiredHops + 1} reviews for this call before anyone sealed them, so the guard stopped asking and nothing was run. ` +
              `Do not run it. Ask the person whether they still want it${ask}. Latest review: ${reviewUrl}.`
          );
        }
        expiredHops++;
        ref = nextRef(ref, captureId);
        continue;
      }
      return outcome.output;
    }
  } catch (error) {
    if (error instanceof Stop) return deny(error.reason);
    throw error;
  }
}

/** The branch checked out in `cwd`, or null (no cwd, not a repository, a detached HEAD, any error). */
export function currentBranch(cwd) {
  if (typeof cwd !== "string" || cwd === "") return null;
  try {
    const branch = execFileSync(
      "git",
      ["-C", cwd, "rev-parse", "--abbrev-ref", "HEAD"],
      { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 5_000 }
    ).trim();
    return branch === "" || branch === "HEAD" ? null : branch;
  } catch {
    return null;
  }
}
