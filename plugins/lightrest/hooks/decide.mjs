// SPDX-License-Identifier: Apache-2.0
/**
 * The action guard's decision: given the call the agent is about to run and
 * what `get_review` says about its authorisation, allow it, allow it with the
 * reviewer's edits, refuse it, or say the review is still open.
 *
 * Pure. No network, no file system, no process. The entry script owns the
 * request, the polling and the printing; this file turns one `get_review`
 * answer (its `structuredContent`) into one hook output.
 * Design: docs/superpowers/specs/2026-10-21-action-guard-design.md §4.
 *
 * What it reads from the answer (server/mcp/tools.ts `reviewResultFor`):
 *   status                     pending | sealed | credentialed | awaiting_witness | discarded | expired
 *   action.authorised          the call the reviewer authorised ({tool, arguments}), or null
 *   action.diff                {toolChanged, changedPaths, addedPaths, removedPaths}, RFC 6901 pointers
 *   review.decision            approved_unchanged | approved_edited | overridden | rejected
 *   review.verifyUrl           present once a credential exists
 *   review.contentCustody      "local" when LightRest holds digests, not the call
 *
 * Any sealed status counts as sealed, witness or not: a record still waiting
 * for its witness's co-signature is the reviewer's decision all the same.
 * Anything this file cannot read is a deny, never an allow.
 *
 * This is a seatbelt against an agent's honest mistakes, not a security
 * boundary.
 */
import canonicalize from "./jcs.mjs";

/** The statuses of a review its reviewer has sealed. */
const SEALED_STATUSES = new Set(["sealed", "credentialed", "awaiting_witness"]);

const isObject = value =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * The hook output that stops a call.
 * @param {string} reason
 */
export function deny(reason) {
  return {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: reason,
    },
  };
}

/**
 * The hook output that lets a call run. `updatedInput` replaces the tool's
 * input, so it is added when there is one and left out otherwise.
 *
 * Claude Code shows `permissionDecisionReason` to the agent for a deny only;
 * for an allow it goes to the debug log. The agent must still be told when its
 * call was edited, so the same words are sent as `additionalContext`, which
 * it does read.
 * @param {string} reason
 * @param {object} [updatedInput]
 */
export function allow(reason, updatedInput) {
  const hookSpecificOutput = {
    hookEventName: "PreToolUse",
    permissionDecision: "allow",
    permissionDecisionReason: reason,
    additionalContext: reason,
  };
  if (updatedInput !== undefined)
    hookSpecificOutput.updatedInput = updatedInput;
  return { hookSpecificOutput };
}

const done = output => ({ final: true, output });

/**
 * @param {{tool: string, arguments: object}} proposed the call the agent is about to run
 * @param {object} sc the `structuredContent` of the `get_review` answer
 * @param {string} reviewUrl the review link `request_action_review` returned
 * @param {{baseInput?: object}} [options] `baseInput` is the tool's whole input
 *   when the proposal is a part of it (a shell tool: the proposal is
 *   `{command}`, the input also holds description, timeout and the like). The
 *   authorised call is then read for its `command` alone, and an edit runs as
 *   `baseInput` with that command put in, so the other fields are kept.
 * @returns {{final: true, output: object} | {final: false}} `final: false` means the review is still open
 */
export function decide(proposed, sc, reviewUrl, options = {}) {
  const status = isObject(sc) ? sc.status : undefined;
  const name = toolName(proposed);

  if (status === "pending") return { final: false };

  // `run` (guard-lib.mjs) never prints this reason: on an expired capture it asks
  // again in the same call, up to MAX_HOPS times, and ends with its own deny. It
  // still needs this answer to be final, which is how the poll loop ends, and a
  // caller that does not hop gets a deny that says what happened rather than
  // "status not recognised". So the branch stays, and its test pins the words.
  if (status === "expired") {
    return done(
      deny(
        `Your review expired before anyone sealed it; nothing was run. ` +
          `Call it again to ask for a new review. Review link: ${reviewUrl}.`
      )
    );
  }
  if (status === "discarded") {
    return done(
      deny(
        `A reviewer discarded the authorisation request, so ${name} was not run. ` +
          `Do not run it. Ask the person whether they still want it. Review link: ${reviewUrl}.`
      )
    );
  }

  if (SEALED_STATUSES.has(status))
    return done(decideSealed(proposed, sc, reviewUrl, options.baseInput));

  const named =
    typeof status === "string" && status.length > 0 && status.length <= 40
      ? ` (status "${status}")`
      : "";
  return done(
    deny(
      `LightRest answered with a review status this guard does not recognise${named}, so ${name} was not run. ` +
        `Do not run it. Ask the person to check the review at ${reviewUrl}.`
    )
  );
}

function toolName(proposed) {
  return isObject(proposed) &&
    typeof proposed.tool === "string" &&
    proposed.tool.length > 0
    ? proposed.tool
    : "this call";
}

function decideSealed(proposed, sc, reviewUrl, baseInput) {
  const name = toolName(proposed);
  const action = isObject(sc.action) ? sc.action : null;

  // A sealed reply always carries its review block (decision, custody, verify
  // link). Without it the guard cannot tell a rejection or a held call from an
  // authorisation, so it fails closed.
  if (!isObject(sc.review)) {
    return deny(
      `The reply about this review was incomplete (it had no review details), so nothing was run. ` +
        `Do not run it. Ask the person to check the review at ${reviewUrl}.`
    );
  }
  const review = sc.review;

  // The decision comes first: a rejection authorises nothing, whatever else
  // the reply carries.
  if (review.decision === "rejected") {
    return deny(
      `Your reviewer rejected this call, so ${name} was not run. ` +
        `Do not run it again or look for another way to do the same thing. ` +
        `Ask the person what they want done instead. Review link: ${reviewUrl}.`
    );
  }

  if (action === null || action.authorised === undefined) {
    return deny(
      `The review is sealed but its reply does not say which call was authorised, so ${name} was not run. ` +
        `Do not run it. Ask the person to check the review at ${reviewUrl}.`
    );
  }

  let authorised = action.authorised;
  if (authorised === null) {
    if (review.contentCustody === "local") {
      return deny(
        `The authorised call is kept by your organisation; nothing was run. ` +
          `The review was sealed under local custody, so LightRest holds a digest of the call and cannot hand the call back. ` +
          `Do not run ${name}. Ask the person who reviewed it what to do. Review link: ${reviewUrl}.`
      );
    }
    return deny(
      `The sealed review has no authorised call, so it counts as rejected and ${name} was not run. ` +
        `Do not run it. Ask the person to open the review at ${reviewUrl} and say what they want done.`
    );
  }

  if (!isCall(authorised) || !isCall(proposed)) {
    return deny(
      `The review is sealed but the call it authorised could not be read, so ${name} was not run. ` +
        `Do not run it. Ask the person to check the review at ${reviewUrl}.`
    );
  }

  if (authorised.tool !== proposed.tool) {
    return deny(
      `Your reviewer authorised ${authorised.tool} instead of ${proposed.tool}, so ${proposed.tool} was not run. ` +
        `Do not run this call again. If you still need the call your reviewer authorised, ask the person for it and make it; ` +
        `the guard checks it like any other call. Review link: ${reviewUrl}.`
    );
  }

  // A shell tool's proposal is its command alone, so the authorised call is
  // read for its command alone: any other key the reviewer put in is not part
  // of the call, and a command that is not a string cannot be run.
  if (baseInput !== undefined) {
    if (typeof authorised.arguments.command !== "string") {
      return deny(
        `The review is sealed but the call it authorised has no command, so ${name} was not run. ` +
          `Do not run it. Ask the person to check the review at ${reviewUrl}.`
      );
    }
    authorised = {
      tool: authorised.tool,
      arguments: { command: authorised.arguments.command },
    };
  }

  // Key order and whitespace must not change the answer, so both calls go
  // through the same canonical form the server sealed.
  let proposedText;
  let authorisedText;
  try {
    proposedText = canonicalize({
      tool: proposed.tool,
      arguments: proposed.arguments,
    });
    authorisedText = canonicalize({
      tool: authorised.tool,
      arguments: authorised.arguments,
    });
  } catch {
    return deny(
      `The call could not be put into a form that can be checked against the authorisation, so ${name} was not run. ` +
        `Do not run it. Ask the person to check the review at ${reviewUrl}.`
    );
  }

  const trailer = verifyNote(review, sc.status);
  if (proposedText === authorisedText) {
    return allow(`Authorised and sealed by your reviewer.${trailer}`);
  }
  return allow(
    `Authorised and sealed by your reviewer, with changes. The call runs with the arguments your reviewer authorised.` +
      `${changeNote(action.diff)}${trailer}`,
    baseInput === undefined
      ? authorised.arguments
      : { ...baseInput, command: authorised.arguments.command }
  );
}

function isCall(call) {
  return (
    isObject(call) &&
    typeof call.tool === "string" &&
    call.tool.length > 0 &&
    isObject(call.arguments)
  );
}

/** The verify link when a credential exists; for a record still waiting for its witness, why there is none yet. */
function verifyNote(review, status) {
  if (typeof review.verifyUrl === "string" && review.verifyUrl.length > 0)
    return ` Verify link: ${review.verifyUrl}.`;
  if (status === "awaiting_witness")
    return " Its witness has not co-signed yet; the record gets its verify link once they do.";
  return "";
}

/** The most paths named in each list. The reason is sent to the model as additionalContext, which Claude Code cuts at 8,000 characters. */
const MAX_PATHS_PER_LIST = 20;
/** The longest a single path is shown, in characters. */
const MAX_PATH_LENGTH = 100;
/** A key name below the top level is shown only when it looks like a name, never like data. */
const PLAIN_KEY = /^[A-Za-z_][A-Za-z0-9_-]{0,63}$/;
const ARRAY_INDEX = /^(?:0|[1-9][0-9]*)$/;

/**
 * One RFC 6901 path as the agent is shown it. An object key can hold data
 * (/arguments/env/TOKEN=sk-live-123), so below `/arguments/<top>` a segment is
 * named only if it is a plain identifier or an array index; any other segment
 * becomes `<key>`. A path that does not start with /arguments/ is not shown.
 */
function showPath(path) {
  const segments = path.split("/");
  if (segments.length < 3 || segments[0] !== "" || segments[1] !== "arguments")
    return "<path>";
  const shown = segments
    .slice(3)
    .map(seg => (PLAIN_KEY.test(seg) || ARRAY_INDEX.test(seg) ? seg : "<key>"));
  const text = ["", "arguments", segments[2], ...shown].join("/");
  return text.length > MAX_PATH_LENGTH
    ? `${text.slice(0, MAX_PATH_LENGTH)}...`
    : text;
}

/**
 * " Changed: /arguments/a. Added: /arguments/b. Removed: /arguments/c." from
 * the server's own diff: where the reviewer changed the call, never what they
 * changed it to. Each list names its first MAX_PATHS_PER_LIST paths and counts
 * the rest.
 */
function changeNote(diff) {
  if (!isObject(diff)) return "";
  const paths = list =>
    Array.isArray(list) ? list.filter(p => typeof p === "string") : [];
  return [
    ["Changed", paths(diff.changedPaths)],
    ["Added", paths(diff.addedPaths)],
    ["Removed", paths(diff.removedPaths)],
  ]
    .filter(([, found]) => found.length > 0)
    .map(([label, found]) => {
      const named = found.slice(0, MAX_PATHS_PER_LIST).map(showPath).join(", ");
      const more = found.length - MAX_PATHS_PER_LIST;
      return ` ${label}: ${named}${more > 0 ? ` and ${more} more` : ""}.`;
    })
    .join("");
}
