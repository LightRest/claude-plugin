// SPDX-License-Identifier: Apache-2.0
/**
 * The action guard's policy: for one tool call, does it pass, wait for a person
 * to authorise it, or get refused outright?
 *
 * Pure. No network, no file system, no process: the git branch lookup is
 * injected (`ctx.currentBranch`), so the entry script owns every side effect.
 * Design: docs/superpowers/specs/2026-10-21-action-guard-design.md §3.
 *
 * This is a seatbelt against an agent's honest mistakes, not a security
 * boundary. A shell command can always be phrased a way this file does not
 * read. Where it cannot tell what a call does, it says `review`.
 *
 * Bash: two readers, and a pass needs both to agree
 * -------------------------------------------------
 * A command is a push to main (or master) if either reader finds one, or finds
 * a push whose destination it cannot rule out. It passes only when neither does.
 * Neither reader is complete. The second exists because the first loses its
 * place on ordinary text; it is simpler, so it pays in false positives.
 *
 * 1. `simpleCommands`, the quote-aware reader, splits the text the way the shell
 *    would: quotes, escapes, `;` `&` `|` newline and parentheses, redirections,
 *    and the bodies of `$(...)` and backticks inside double quotes. It is
 *    precise on plain commands and loses its place on others: it knows nothing
 *    about comments or heredocs, so an apostrophe in either (or in $'...')
 *    makes it read the rest of the text as one quoted word and hide every later
 *    push. It reads the word git only in command position (after env
 *    assignments and a few wrappers) and keeps a later-push fallback
 *    (`git --unknown-option value push ...`).
 * 2. `looseSegments`, the backstop, understands no quoting, and each of its
 *    rules carries a risk:
 *    - It deletes every quote and backslash. Cost: quoted text that reads like a
 *      push (`echo "git push origin main"`) is review.
 *    - It looks for the word git anywhere in a segment, also with a substitution
 *      marker or an option (`-x`, `--exec=`) glued to it. Cost:
 *      prose that spells git push is read as a push.
 *    - It ends a segment at `;` `&` `|` newline, and reads the text six ways:
 *      split at backticks and parentheses, joined across them (a backtick
 *      becomes `$`, `(` a space), and split at newlines only (so a quoted option
 *      value that holds `;` `|` or `&` stays inside its push), each with a
 *      word-initial `#` ending the segment and not ending it. Risk: a joined
 *      reading ends a backtick's command at the first word that carries the
 *      closing `$`; in the newline-only reading a standalone `&&` `;` `|` `&`
 *      word ends a push's arguments only once it has a remote and a refspec,
 *      so a destination placed after a separator-bearing option value that
 *      itself follows two positionals is missed; a quoted `#` is only handled
 *      by the readings where `#` does not cut.
 *    - It reads each segment with redirection targets dropped, kept, and cut
 *      off at the first redirection. Risk: a redirection form it does not know
 *      is read as arguments.
 *    - Its later-push fallback applies whenever a global option was consumed
 *      before the slot word. Cost: `git -C dir stash push -m "wip on main"` (or
 *      a commit message that spells push and main) in front of which sits a
 *      -c/-C is review, because with the quotes gone it has the same shape as
 *      `git -c user.name="a status" push origin main`.
 *    - It walks the segments in order and, after a checkout, switch, `branch
 *      -m`/`-u` or a `config` of push.*, branch.* or remote.*.push, treats the
 *      current branch as unknown for the pushes after it (so a bare push, HEAD
 *      and @ are review). Risk: a change made by a function defined earlier, by
 *      `cd`, or by `export GIT_DIR` is not seen. A push fed by xargs is review.
 *    - It skips a segment that starts with grep, egrep, fgrep, rg, ag or `git
 *      grep` (a pattern is data), unless it carries -O, --open-files-in-pager
 *      or --pre. Risk: a search tool with another option that runs a command.
 *
 * Both readers read the command as written and, when it differs, as PowerShell
 * reads it (`shellReadings`): a backtick right before a newline continues the
 * line there, where Bash would start a substitution; a backslash is a path
 * separator; a comma separates the elements of an argument array. Both take
 * git.exe, git.cmd and a full path to either, in any letter case, for git.
 *
 * Both readers hand what they find to the same helpers: `parseGit` (global
 * options, the subcommand, push options, refspecs, config), `destinationOf`,
 * and `reachesMain` (the branch lookup and the main/HEAD/pattern rules). A
 * mistake in one of those blinds both readers at once, which the two-reader
 * design does not cover.
 *
 * Bash: main moved through the GitHub API (founder ruling, 2026-10-22)
 * --------------------------------------------------------------------
 * A merge, or a write that moves main, made through GitHub's API waits like a
 * push to main. `githubMovesMain` reads the same texts with the same two
 * readers: the first looks at the program in command position, the backstop at
 * gh, curl or wget anywhere in a segment, and either one finding a move is
 * enough. No branch is looked up: what moves is on GitHub.
 * - gh: `pr merge` in any form. `api` writes (a method other than GET or HEAD;
 *   with none, a field or --input, which gh sends as a POST) to a pull
 *   request's merge, to merges, to git/refs naming main or master (in the path,
 *   or in the `ref` field of a new ref), and to contents or merge-upstream
 *   unless a `branch` field names another branch (with --input the body is the
 *   file, so no field is read). `api graphql` with a mutation that merges or
 *   moves a ref (BRANCH_MUTATION, looked for in the whole command, so a query
 *   over several lines is found), or a query read from a file. `repo sync
 *   <repository>` unless --branch names another branch. cobra also reads
 *   options written before the command words, so the command is read with
 *   those options taking the next word and with them not taking it.
 * - curl and wget: a write (-X, --request or --method other than GET or HEAD;
 *   a body without -G; -T; -K; PowerShell's -Method, -Body and -InFile, since
 *   Windows PowerShell runs both as Invoke-WebRequest) to the same routes.
 *   Their body is not read, so a route that depends on a field counts whatever
 *   it names.
 * - any other program: a word that spells a GitHub API URL (api.github.com,
 *   /api/v3/, GITHUB_API_URL) on those routes, or the GraphQL URL with a
 *   mutation in the command. The guard does not read its options, and it may
 *   write, so the URL is enough. In the backstop that holds for a URL with no
 *   gh, curl or wget in front of it in its segment.
 * Branch names are compared in any letter case, and one filled in when the
 * command runs (`$BRANCH`, gh's `{branch}`, `-F branch=@file`) counts as main.
 * The costs are a push's: text that spells `gh pr merge` or such a URL (a
 * commit message, an echo) is review, and so is a read through a program the
 * guard does not read, or one behind an apostrophe in a comment or a heredoc
 * (the first reader takes the rest of the text for one quoted word, which
 * spells the URL). The risk is a push's too: in the newline-only reading a
 * standalone `&&` `;` `|` word ends a client's words once a route has been
 * read, so a method placed after a separator-bearing value that itself follows
 * the route is missed by that reading.
 *
 * Accepted residuals (a seatbelt, not a boundary): git reached through a
 * variable, an alias defined outside the command line, or a function or eval
 * that builds the word git or push at run time; a PowerShell argument array of
 * bare words with a space after each comma (`-ArgumentList push, origin,
 * main`), whose comma reads like prose; an extglob destination such as
 * `!(feature)` (extglob is off by default); unqualified user-defined SQL
 * functions with side effects inside a `select`, and extension functions called
 * without their schema other than the PostGIS ones SIDE_EFFECT_CALL names; a
 * bare push after `cd <dir> &&` (`cd <repo-on-main> && git push` is missed when
 * the session sits on another branch), because its branch is looked up in the
 * session directory, not in <dir>; `export GIT_DIR=...` and other state set by
 * one command for the next; `git fetch . feature:main`; gh reached through an
 * alias or an extension; the GitHub API reached through a variable that holds
 * the whole endpoint or URL (`curl -X PUT "$URL"`) or from a script file, by a
 * program other than gh, curl and wget at a URL that does not name GitHub's API
 * host, and a GraphQL mutation the command does not spell out; a workflow that
 * pushes to main itself, started with gh workflow run or an MCP tool such as
 * actions_run_trigger; a shell tool the matcher and SHELL_TOOLS do not name
 * (Bash, PowerShell and Monitor are the ones Claude Code 2.1.306 has); and, in
 * guard-lib.mjs, the cap of 4 authorisations of one identical call per session
 * (the first, and 3 asked again after a seal went stale). The plugin README's
 * "Accepted limits" repeats this list.
 */
import { basename, resolve } from "node:path";

const LIST_OR_GET = /^(?:list|get)_/;

/**
 * One entry per guarded server. `refuse` is the set of calls that are never
 * sent for review (the founder's credential acts); `pass` says which calls are
 * plainly reads; anything else on the server is `review`, so a tool added next
 * month is guarded before anyone lists it. `reason`, when given, is what a
 * review says instead of "not a plain read". Keys are lower case.
 *
 * GitHub is the other way round (founder ruling, 2026-10-22): most of its tools
 * (issues, comments, pull requests, reads) cannot move a branch, so `pass` is
 * everything but the calls that can move main (`githubToolMovesMain`).
 */
const SERVERS = new Map([
  [
    "supabase",
    {
      label: "Supabase",
      refuse: new Set(["create_edge_function_secret"]),
      // Setting a Vault secret is a credential act too, in any SQL that says so.
      refuseCall: (tool, input) =>
        (tool === "execute_sql" || tool === "apply_migration") &&
        writesVaultSecret(input.query)
          ? `${"Supabase"} ${tool} sets a secret (vault.create_secret or vault.update_secret), which is one of your credential acts, so the guard does not send it for review. Ask the person to set the secret in the Supabase dashboard.`
          : null,
      pass: (tool, input) =>
        LIST_OR_GET.test(tool) ||
        tool === "search_docs" ||
        tool === "generate_typescript_types" ||
        tool === "query_logs" ||
        (tool === "execute_sql" && isReadOnlySql(input.query)),
    },
  ],
  [
    "railway",
    {
      label: "Railway",
      refuse: new Set([
        "set-variables",
        "list-variables",
        "get-bucket-credentials",
        "reset-bucket-credentials",
      ]),
      pass: tool =>
        /^(?:list|describe|search|http)-/.test(tool) ||
        /-status$/.test(tool) ||
        (tool.startsWith("get-") && !tool.includes("credential")) ||
        tool === "fetch-docs" ||
        tool === "whoami",
    },
  ],
  [
    "stripe",
    {
      label: "Stripe",
      refuse: new Set(),
      pass: tool =>
        /^(?:list|retrieve|search|get)_/.test(tool) || tool.startsWith("fetch"),
    },
  ],
  [
    "github",
    {
      label: "GitHub",
      refuse: new Set(),
      pass: (tool, input) => !githubToolMovesMain(tool, input),
      reason: tool =>
        `GitHub ${tool} may merge into or update main or master, which deploys to production, so it waits for a person to authorise it.`,
    },
  ],
]);

/** The GitHub MCP tools that merge a pull request. Their arguments do not name the base branch, so they always wait. */
const GITHUB_MERGE_TOOLS = new Set([
  "merge_pull_request",
  "enable_pr_auto_merge",
]);
/** The GitHub MCP tools that commit to the branch in their `branch` argument, or to the default branch without one. */
const GITHUB_FILE_TOOLS = new Set([
  "push_files",
  "create_or_update_file",
  "delete_file",
]);

/** Can this GitHub MCP call (tool name in lower case) move main or master? */
function githubToolMovesMain(tool, input) {
  if (GITHUB_MERGE_TOOLS.has(tool)) return true;
  if (GITHUB_FILE_TOOLS.has(tool)) return namesMain(input.branch);
  return false;
}

const pass = () => ({ action: "pass", reason: "" });

/**
 * The tools that run a shell command text from their `command` input field.
 * Read from Claude Code 2.1.306 (the tool definitions in the installed binary):
 * Bash and PowerShell (both `ruleContentField: "command"`) and Monitor
 * (`command`, or `ws` for a WebSocket: exactly one of the two, so a Monitor on
 * a WebSocket has no command and passes). Their command text is read the same
 * way, with the Bash readers, once as written and once as PowerShell reads it
 * (`shellReadings`): beyond that and what the quote-blind second reader already
 * ignores, the git push rules do not depend on the shell's dialect.
 * hooks.json's matcher names the same tools; a test pins the two together.
 */
export const SHELL_TOOLS = new Set(["Bash", "PowerShell", "Monitor"]);

/**
 * @param {string} toolName
 * @param {unknown} toolInput
 * @param {{ currentBranch: (cwd: string | undefined) => string | null, cwd?: string }} ctx
 * @returns {{ action: "pass" | "review" | "refuse", reason: string }}
 */
export function classify(toolName, toolInput, ctx = {}) {
  const input =
    toolInput !== null && typeof toolInput === "object" ? toolInput : {};

  if (SHELL_TOOLS.has(toolName)) {
    const command = input.command;
    if (typeof command !== "string") return pass();
    if (pushTargetsMain(command, ctx.currentBranch, ctx.cwd)) {
      return {
        action: "review",
        reason:
          "This git push may update main or master, which deploys to production, so it waits for a person to authorise it.",
      };
    }
    if (githubMovesMain(command)) {
      return {
        action: "review",
        reason:
          "This GitHub API call may merge into or update main or master, which deploys to production, so it waits for a person to authorise it.",
      };
    }
    return pass();
  }

  const parsed =
    typeof toolName === "string" ? /^mcp__(.+?)__(.+)$/i.exec(toolName) : null;
  if (!parsed) return pass();
  const server = SERVERS.get(guardedServer(parsed[1].toLowerCase()) ?? "");
  if (!server) return pass();

  const tool = parsed[2];
  const key = tool.toLowerCase();
  if (server.refuse.has(key)) {
    return {
      action: "refuse",
      reason:
        `${server.label} ${tool} is one of your credential acts, so the guard does not send it for review. ` +
        `Ask the person to do it in the ${server.label} dashboard.`,
    };
  }
  const refusedCall = server.refuseCall?.(key, input);
  if (refusedCall) return { action: "refuse", reason: refusedCall };
  if (server.pass(key, input)) return pass();
  return {
    action: "review",
    reason:
      server.reason?.(tool) ??
      `${server.label} ${tool} is not a plain read, so it waits for a person to authorise it.`,
  };
}

/**
 * The guarded server a `mcp__<server>__<tool>` segment names (lower case). A
 * segment is guarded when a guarded name is one of its tokens, a run between
 * `-` or `_`: `supabase`, `supabase-prod`, `supabase_lightrest`, `stripe-live`,
 * and the prefixes a plugin or a claude.ai connector puts in front
 * (`plugin_x_supabase`, `claude_ai_Supabase`). It fails closed on purpose: a
 * server someone named `supabase_notes` is reviewed too, because a name cannot
 * say what a server does. A name that merely contains the word (`notstripe`,
 * `stripey`, `oursupabase`) is not guarded: the token has to stand alone. The
 * first guarded token in the segment picks the server.
 */
function guardedServer(segment) {
  for (const token of segment.split(/[-_]/)) {
    if (SERVERS.has(token)) return token;
  }
  return null;
}

// ---------------------------------------------------------------------------
// SQL
// ---------------------------------------------------------------------------

// PostgreSQL counts every character from U+0080 up as part of an identifier,
// so a dollar-quote tag, or the word before a `$`, can hold them.
const NON_ASCII = "\\u0080-\\uffff";
const IDENT = new RegExp(`[A-Za-z0-9_$${NON_ASCII}]`);
const DOLLAR_TAG = new RegExp(
  `^\\$(?:[A-Za-z_${NON_ASCII}][A-Za-z0-9_${NON_ASCII}]*)?\\$`
);

/**
 * The statement with comments, string literals, quoted identifiers and
 * dollar-quoted bodies replaced by a space, or null when one of them is left
 * open. One pass, so a quote inside a comment, or a comment marker inside a
 * string, is read the way the database reads it.
 *
 * `named` is the same text with each quoted identifier put back as its name
 * (`"cron"."schedule"(` reads `cron.schedule(`), for finding what a call
 * names. Keywords are looked for in `code`, where a quoted `"update"` is blank.
 */
function stripSql(sql) {
  let code = "";
  let named = "";
  let i = 0;
  const n = sql.length;
  const blank = () => {
    code += " ";
    named += " ";
  };
  while (i < n) {
    const c = sql[i];
    const d = sql[i + 1];

    if (c === "-" && d === "-") {
      // A comment ends at the first CR or LF.
      while (i < n && sql[i] !== "\n" && sql[i] !== "\r") i++;
      blank();
      continue;
    }

    if (c === "/" && d === "*") {
      let depth = 1;
      i += 2;
      while (i < n && depth > 0) {
        if (sql[i] === "/" && sql[i + 1] === "*") {
          depth++;
          i += 2;
        } else if (sql[i] === "*" && sql[i + 1] === "/") {
          depth--;
          i += 2;
        } else {
          i++;
        }
      }
      if (depth > 0) return null;
      blank();
      continue;
    }

    if (c === "'") {
      // E'...' lets a backslash escape the quote; a plain string does not.
      const escapes =
        (sql[i - 1] === "e" || sql[i - 1] === "E") &&
        !(i >= 2 && IDENT.test(sql[i - 2]));
      let closed = false;
      i++;
      while (i < n) {
        if (escapes && sql[i] === "\\") {
          i += 2;
        } else if (sql[i] === "'" && sql[i + 1] === "'") {
          i += 2;
        } else if (sql[i] === "'") {
          closed = true;
          i++;
          break;
        } else {
          i++;
        }
      }
      if (!closed) return null;
      blank();
      continue;
    }

    if (c === '"') {
      // U&"\0063ron" spells cron with an escape: the text is not the name, so
      // nothing below could check it. Doubtful, so not read-only.
      if (sql[i - 1] === "&" && (sql[i - 2] === "U" || sql[i - 2] === "u"))
        return null;
      let closed = false;
      let name = "";
      i++;
      while (i < n) {
        if (sql[i] === '"' && sql[i + 1] === '"') {
          name += '"';
          i += 2;
        } else if (sql[i] === '"') {
          closed = true;
          i++;
          break;
        } else {
          name += sql[i];
          i++;
        }
      }
      if (!closed) return null;
      code += " ";
      named += name;
      continue;
    }

    if (c === "$" && !(i > 0 && IDENT.test(sql[i - 1]))) {
      const tag = DOLLAR_TAG.exec(sql.slice(i));
      if (tag) {
        const end = sql.indexOf(tag[0], i + tag[0].length);
        if (end < 0) return null;
        i = end + tag[0].length;
        blank();
        continue;
      }
    }

    code += c;
    named += c;
    i++;
  }
  return { code, named };
}

// Keyword boundaries stay ASCII on purpose: a keyword touching a non-ASCII
// letter still counts, which can only make the answer "not read-only".
const WRITE_WORDS =
  /(?<![A-Za-z0-9_$])(?:insert|update|delete|merge|create|alter|drop|truncate|grant|revoke|copy|call|do|set|vacuum|refresh|security|into)(?![A-Za-z0-9_$])/i;
const LEADING_WORD = new RegExp(
  `^\\s*([A-Za-z]+)(?![A-Za-z0-9_$${NON_ASCII}])`
);
const EXPLAIN_ANALYZE = /(?<![A-Za-z0-9_$])analy[sz]e(?![A-Za-z0-9_$])/i;

/**
 * Calls that change something although the statement is a SELECT, or that run
 * SQL (or name a relation) from a string the literal-stripping cannot see
 * (query_to_xml and its family, ts_stat, ts_rewrite).
 * Matched on the name followed by `(`, so reading a table (`from cron.job`) is
 * not one. The list applies whatever the schema, so `pg_catalog.set_config(` is
 * on it too. Production runs pg_cron (`cron.`) and pg_net (`net.`). Supabase
 * installs extensions into `extensions`, which is on the search path, so they
 * are called unqualified: PostGIS's functions that run DROP TABLE, ALTER TABLE,
 * CREATE INDEX or ALTER EXTENSION, or write its lock tables, are on it.
 */
const SIDE_EFFECT_CALL = new RegExp(
  `(?<![A-Za-z0-9_$${NON_ASCII}])(?:` +
    `(?:cron|net)\\s*\\.\\s*[A-Za-z_${NON_ASCII}][A-Za-z0-9_$${NON_ASCII}]*` +
    "|dblink[A-Za-z0-9_$]*" +
    "|pg_terminate_backend|pg_cancel_backend|pg_reload_conf|pg_rotate_logfile" +
    "|pg_notify" +
    "|set_config|setval|nextval" +
    "|ts_stat|ts_rewrite" +
    "|lo_[A-Za-z0-9_$]*" +
    "|query_to_xml[A-Za-z0-9_$]*" +
    "|table_to_xml[A-Za-z0-9_$]*" +
    "|schema_to_xml[A-Za-z0-9_$]*" +
    "|database_to_xml[A-Za-z0-9_$]*" +
    "|cursor_to_xml[A-Za-z0-9_$]*" +
    "|http[A-Za-z0-9_$]*" +
    "|(?:add|drop)geometrycolumn|dropgeometrytable|populate_geometry_columns" +
    "|(?:add|drop)(?:raster|overview)constraints|update(?:geometry|raster)srid" +
    "|(?:enable|disable)longtransactions|lockrow|unlockrows|addauth" +
    "|install_missing_indexes|postgis_extensions_upgrade" +
    ")\\s*\\(",
  "i"
);

/** `schema.name(`: the schema is captured. Chains match their last pair. */
const QUALIFIED_CALL = new RegExp(
  `(?<![A-Za-z0-9_$${NON_ASCII}])([A-Za-z_${NON_ASCII}][A-Za-z0-9_$${NON_ASCII}]*)\\s*\\.\\s*[A-Za-z_${NON_ASCII}][A-Za-z0-9_$${NON_ASCII}]*\\s*\\(`,
  "g"
);
/** The schemas whose functions are the database's own. */
const BUILT_IN_SCHEMAS = new Set(["pg_catalog", "information_schema"]);

/** `pg_name(`, qualified or not: the name is captured. */
const PG_CALL = new RegExp(
  `(?<![A-Za-z0-9_$${NON_ASCII}])(pg_[A-Za-z0-9_$${NON_ASCII}]*)\\s*\\(`,
  "gi"
);
/** The pg_* functions that only read. Anything else named pg_ is doubtful. */
const READ_PG_PREFIXES = [
  "pg_get_",
  "pg_is_",
  "pg_current_",
  "pg_last_",
  "pg_stat_get_",
];
const READ_PG_NAMES = new Set([
  "pg_size_pretty",
  "pg_total_relation_size",
  "pg_relation_size",
  "pg_table_size",
  "pg_indexes_size",
  "pg_database_size",
  "pg_tablespace_size",
  "pg_column_size",
  "pg_typeof",
  "pg_has_role",
  "pg_table_is_visible",
  "pg_backend_pid",
  "pg_postmaster_start_time",
  "pg_conf_load_time",
  "pg_encoding_to_char",
  "pg_describe_object",
  "pg_identify_object",
  "pg_blocking_pids",
  "pg_wal_lsn_diff",
  "pg_input_is_valid",
  "pg_jit_available",
]);

/**
 * Does the statement call something that may write, run a string as SQL, or is
 * simply unknown? Fails closed: a call into any schema but pg_catalog and
 * information_schema (production has wrappers such as lr_monitor.send_mail, and
 * extensions such as graphql.resolve), and a pg_* function that is not a known
 * read, are doubtful. `named` is the text with quoted names put back.
 */
function callsSomethingDoubtful(named) {
  if (SIDE_EFFECT_CALL.test(named)) return true;
  for (const m of named.matchAll(QUALIFIED_CALL)) {
    if (!BUILT_IN_SCHEMAS.has(m[1].toLowerCase())) return true;
  }
  for (const m of named.matchAll(PG_CALL)) {
    const name = m[1].toLowerCase();
    if (
      !READ_PG_NAMES.has(name) &&
      !READ_PG_PREFIXES.some(p => name.startsWith(p))
    )
      return true;
  }
  return false;
}

/**
 * A call that sets a Vault secret, in the text with comments and strings
 * stripped and quoted names put back (the raw text is searched too, below).
 */
const VAULT_SECRET_WRITE = new RegExp(
  `(?<![A-Za-z0-9_$${NON_ASCII}])vault\\s*\\.\\s*(?:create_secret|update_secret)\\s*\\(`,
  "i"
);
/**
 * The same call in the RAW text, so it is found inside a `$$` body or a function
 * body too: whitespace, block comments and quotes may sit between the tokens.
 * A mention in a comment or a string refuses as well (accepted).
 */
const SQL_GAP = "(?:\\s|/\\*[\\s\\S]*?\\*/|--[^\\n]*\\n)*";
const VAULT_SECRET_RAW = new RegExp(
  `(?<![A-Za-z0-9_$${NON_ASCII}])"?vault"?${SQL_GAP}\\.${SQL_GAP}"?(?:create|update)_secret"?${SQL_GAP}\\(`,
  "i"
);
function writesVaultSecret(query) {
  if (typeof query !== "string") return false;
  if (VAULT_SECRET_RAW.test(query)) return true;
  const stripped = stripSql(query);
  return stripped !== null && VAULT_SECRET_WRITE.test(stripped.named);
}

/**
 * A reference to the vault schema, as the qualifier of a name. vault holds the
 * project's secrets and `vault.decrypted_secrets` is a view over them, so
 * reading it is no call yet hands secrets to the agent: it is never a plain
 * read. `public.vaults` and `myvault.x` are other names and do not match.
 */
const VAULT_SCHEMA = new RegExp(
  `(?<![A-Za-z0-9_$${NON_ASCII}])vault\\s*\\.`,
  "i"
);

/**
 * Is this plainly a read? One statement that starts with SELECT, WITH or
 * EXPLAIN (not EXPLAIN ANALYZE, which runs the statement), holds none of the
 * write keywords once comments and strings are set aside, calls nothing that
 * writes or that it cannot vouch for, and does not touch the vault schema.
 * Anything doubtful is false.
 */
export function isReadOnlySql(sql) {
  if (typeof sql !== "string") return false;
  const stripped = stripSql(sql);
  if (stripped === null) return false;
  const body = stripped.code.replace(/[\s;]+$/, "");
  if (body.includes(";")) return false;
  const first = LEADING_WORD.exec(body);
  if (!first) return false;
  const lead = first[1].toLowerCase();
  if (lead !== "select" && lead !== "with" && lead !== "explain") return false;
  if (lead === "explain" && EXPLAIN_ANALYZE.test(body)) return false;
  if (WRITE_WORDS.test(body)) return false;
  return (
    !callsSomethingDoubtful(stripped.named) &&
    !VAULT_SCHEMA.test(stripped.named)
  );
}

// ---------------------------------------------------------------------------
// Bash: git push
// ---------------------------------------------------------------------------

/** The index of the `)` that closes a `$(` whose body starts at `from`, or the end of the line. */
function closingParen(line, from) {
  let depth = 1;
  for (let j = from; j < line.length; j++) {
    const c = line[j];
    if (c === "\\") {
      j++;
    } else if (c === "'") {
      const end = line.indexOf("'", j + 1);
      j = end < 0 ? line.length : end;
    } else if (c === '"') {
      for (j++; j < line.length && line[j] !== '"'; j++) {
        if (line[j] === "\\") j++;
      }
    } else if (c === "(") {
      depth++;
    } else if (c === ")" && --depth === 0) {
      return j;
    }
  }
  return line.length;
}

/** The index of the backtick that closes one whose body starts at `from`, or the end of the line. */
function closingBacktick(line, from) {
  for (let j = from; j < line.length; j++) {
    if (line[j] === "\\") j++;
    else if (line[j] === "`") return j;
  }
  return line.length;
}

/**
 * The simple commands in a shell line, each as its words with quotes removed.
 * Quote aware, so `echo "a; git push origin main"` is one command, not two.
 * Redirections such as `2>&1` stay inside their word. Inside double quotes the
 * shell still runs `$(...)` and backticks, so their bodies are read as command
 * lines of their own.
 */
function simpleCommands(line) {
  const commands = [];
  const substituted = [];
  let words = [];
  let word = "";
  let started = false;
  const endWord = () => {
    if (started) words.push(word);
    word = "";
    started = false;
  };
  const endCommand = () => {
    endWord();
    if (words.length > 0) commands.push(words);
    words = [];
  };
  const n = line.length;
  for (let i = 0; i < n; i++) {
    const c = line[i];
    if (c === "\\") {
      if (line[i + 1] === "\n") {
        i++;
      } else {
        if (i + 1 < n) i++;
        word += line[i];
        started = true;
      }
    } else if (c === "'") {
      const end = line.indexOf("'", i + 1);
      const stop = end < 0 ? n : end;
      word += line.slice(i + 1, stop);
      started = true;
      i = stop;
    } else if (c === '"') {
      i++;
      while (i < n && line[i] !== '"') {
        if (line[i] === "\\" && '"\\$`'.includes(line[i + 1] ?? "\0")) {
          i++;
          word += line[i];
        } else if (line[i] === "\\" && line[i + 1] === "\n") {
          i++;
        } else if (line[i] === "$" && line[i + 1] === "(") {
          const end = closingParen(line, i + 2);
          substituted.push(...simpleCommands(line.slice(i + 2, end)));
          word += line.slice(i, end + 1);
          i = end;
        } else if (line[i] === "`") {
          const end = closingBacktick(line, i + 1);
          substituted.push(...simpleCommands(line.slice(i + 1, end)));
          word += line.slice(i, end + 1);
          i = end;
        } else {
          word += line[i];
        }
        i++;
      }
      started = true;
    } else if (c === " " || c === "\t" || c === "\r") {
      endWord();
    } else if (
      c === "&" &&
      (line[i - 1] === ">" || line[i - 1] === "<" || line[i + 1] === ">")
    ) {
      word += c;
      started = true;
    } else if (";&|\n()`".includes(c)) {
      endCommand();
    } else {
      word += c;
      started = true;
    }
  }
  endCommand();
  const all = commands.concat(substituted);
  all.nestedFrom = commands.length;
  return all;
}

/**
 * Is this word the program git? Windows also runs it as git.exe or git.cmd, by
 * a full path written with backslashes, and in any letter case (so does a
 * case-insensitive macOS volume). Each extra spelling can only add reviews.
 */
const isGitProgram = word =>
  /^git(?:\.(?:exe|cmd|bat))?$/i.test(basename(word.replace(/\\/g, "/")));

const ENV_ASSIGNMENT = /^([A-Za-z_][A-Za-z0-9_]*)=/;
/** Words that can stand in front of a command without changing what it is. */
const PREFIX_WORDS = new Set([
  "if",
  "then",
  "else",
  "elif",
  "do",
  "while",
  "until",
  "!",
  "{",
  "time",
  "command",
  "exec",
  "nohup",
  "sudo",
]);
/** git's own options that take their value as the next word. */
const GIT_OPTIONS_WITH_VALUE = new Set([
  "--namespace",
  "--super-prefix",
  "--attr-source",
]);
/**
 * git push's long options that take their value as the next word. git accepts
 * any unique prefix (`--push-opt`); an ambiguous prefix is an error, so treating
 * every prefix alike errs only toward review.
 */
const PUSH_LONG_OPTIONS_WITH_VALUE = [
  "--repo",
  "--push-option",
  "--receive-pack",
  "--exec",
  "--recurse-submodules",
];
/** The same for `git subtree push`. */
const SUBTREE_LONG_OPTIONS_WITH_VALUE = ["--prefix", "--message", "--onto"];

/**
 * Does this option word take the next word as its value? `-o X`, `-uo X` (the
 * `o` last in a cluster; `-oX` and `-uoX` carry the value themselves),
 * `--push-option X`, `--recurse-submodules on-demand`, and their unique
 * prefixes; `--x=value` carries its value.
 */
function takesNextWord(a, subtree) {
  if (a.startsWith("--")) {
    if (a.includes("=") || a.length <= 2) return false;
    const longs = subtree
      ? SUBTREE_LONG_OPTIONS_WITH_VALUE
      : PUSH_LONG_OPTIONS_WITH_VALUE;
    return longs.some(o => o.startsWith(a));
  }
  const cluster = /^-([A-Za-z0-9]+)$/.exec(a);
  if (!cluster) return false;
  const flags = cluster[1];
  const letter = subtree ? /[Pm]/ : /o/;
  const at = flags.search(letter);
  return at >= 0 && at === flags.length - 1;
}

const REDIRECTION = /^(?:\d+|&|\{[A-Za-z_]\w*\})?(?:>&|<&|>>?|<<?<?)(.*)$/s;

/** The words of a command with its redirections (and their targets) removed. */
function withoutRedirections(words) {
  const kept = [];
  for (let i = 0; i < words.length; i++) {
    const r = REDIRECTION.exec(words[i]);
    if (!r) {
      kept.push(words[i]);
    } else if (r[1] === "") {
      i++;
    }
  }
  return kept;
}

/**
 * Does this git config setting (`key=value`, as -c and --config-env give it)
 * change where a push goes? remote.<name>.push and remote.<name>.mirror supply
 * the refspec of a bare push; push.default picks what a bare push pushes.
 */
function setsPushTarget(setting) {
  const key = String(setting ?? "").split("=", 1)[0];
  if (/^remote\..+\.push$/i.test(key)) return "map";
  if (/^remote\..+\.mirror$/i.test(key) || /^push\.default$/i.test(key))
    return "default";
  return null;
}

/**
 * Does this git config setting define a command name or fix a typo? Either lets
 * a command that never says "push" push (`-c alias.ship=push ship origin main`,
 * `-c help.autocorrect=immediate psuh origin main`).
 */
function setsAlias(setting) {
  const key = String(setting ?? "").split("=", 1)[0];
  return /^alias\./i.test(key) || /^help\.autocorrect$/i.test(key);
}

/** The long options that push every branch. git accepts any unique prefix. */
const EVERY_BRANCH_OPTIONS = ["--all", "--branches", "--mirror"];
const isEveryBranchOption = a =>
  a.length > 2 && EVERY_BRANCH_OPTIONS.some(o => o.startsWith(a));

/**
 * If this command is `git ... push ...` (after env assignments and plain
 * wrapper words), what it asks for; otherwise null.
 */
function parsePush(words) {
  let i = 0;
  let elsewhere = false;
  while (i < words.length) {
    const assignment = ENV_ASSIGNMENT.exec(words[i]);
    if (assignment) {
      if (assignment[1] === "GIT_DIR" || assignment[1] === "GIT_WORK_TREE")
        elsewhere = true;
    } else if (!PREFIX_WORDS.has(words[i])) {
      break;
    }
    i++;
  }
  if (i >= words.length || !isGitProgram(words[i])) return null;
  return parseGit(words, i, elsewhere);
}

/**
 * Reads git's global options from `gitAt + 1`: `i` ends at the subcommand slot.
 */
function readGlobalOptions(words, gitAt, elsewhere) {
  let i = gitAt + 1;
  let risky = false;
  let configRisk = false; // push.default, remote.*.mirror: matters with no refspec
  let mapRisk = false; // remote.*.push: also maps a refspec that has no colon
  const dirs = [];
  const readConfig = setting => {
    if (setsAlias(setting)) risky = true;
    else {
      const kind = setsPushTarget(setting);
      if (kind === "map") mapRisk = true;
      else if (kind === "default") configRisk = true;
    }
  };
  for (; i < words.length; i++) {
    const w = words[i];
    if (w === "-C") {
      dirs.push(words[++i] ?? "");
    } else if (w === "-c" || w === "--config-env") {
      readConfig(words[++i]);
    } else if (w.startsWith("--config-env=")) {
      readConfig(w.slice("--config-env=".length));
    } else if (w.startsWith("--git-dir") || w.startsWith("--work-tree")) {
      elsewhere = true;
      if (!w.includes("=")) i++;
    } else if (GIT_OPTIONS_WITH_VALUE.has(w)) {
      i++;
    } else if (!w.startsWith("-")) {
      break;
    }
  }
  return { i, risky, configRisk, mapRisk, dirs, elsewhere };
}

/**
 * Does this git command change which branch is checked out, or where a bare
 * push goes: checkout or switch with any target (`-`, `-b`, `-c`, `--orphan`
 * count: the new name could be main), `branch -m` / `-M` / `--move` and the
 * upstream options, and `config` of push.*, branch.* or remote.*.push? A
 * checkout with paths after `--` only restores files. Used to treat the branch
 * as unknown for later pushes.
 */
function changesBranch(words, gitAt) {
  const { i } = readGlobalOptions(words, gitAt, false);
  const sub = words[i];
  const args = words.slice(i + 1);
  if (sub === "checkout" || sub === "switch") {
    const dashes = args.indexOf("--");
    return !(dashes >= 0 && dashes < args.length - 1);
  }
  if (sub === "branch")
    return args.some(
      a =>
        a === "--move" ||
        /^-[A-Za-z]*[mMu][A-Za-z]*$/.test(a) ||
        /^--(?:set-upstream-to|track|unset-upstream)/.test(a)
    );
  // git config push.default upstream, branch.<x>.merge, remote.<x>.push: where a
  // bare push goes. Reading a setting changes nothing.
  if (sub === "config")
    return (
      !args.some(a => /^(?:--get|--list$|-l$)/.test(a)) &&
      args.some(a =>
        /^(?:push\.|branch\.|remote\.[^.]+\.(?:push|mirror))/i.test(a)
      )
    );
  return false;
}

/**
 * The part of `parsePush` that starts at the word git (`gitAt`), shared by both
 * readers. `dirs` are the `-C` values in order; `elsewhere` is true when git was
 * pointed at a repository by --git-dir, --work-tree, GIT_DIR or GIT_WORK_TREE;
 * `risky` is true when something makes the destination unknowable (an alias or
 * autocorrect setting, a config that sets the default refspec of a push that
 * gives none, a brace expansion).
 */
function parseGit(
  words,
  gitAt,
  elsewhere,
  afterOptionOnly = false,
  standaloneEnds = false
) {
  const options = readGlobalOptions(words, gitAt, elsewhere);
  let { i, risky, configRisk, mapRisk, dirs } = options;
  elsewhere = options.elsewhere;
  let subtree = false;
  if (words[i] === "subtree" && words[i + 1] === "push") {
    // git subtree push --prefix=sub <remote> <ref>: a push to <ref>
    subtree = true;
    i++;
  }
  if (words[i] !== "push" && words[i] !== "send-pack") {
    // An option this reader does not know, which takes a value as the next
    // word, leaves that value in the subcommand slot. If `push` comes later,
    // read the command from there. The backstop (`afterOptionOnly`) does that
    // only when a global option was consumed before the slot word: with the
    // quotes gone, `git -c user.name="a status" push origin main` and `git -C
    // dir stash push -m "wip on main"` have the same shape, and only the
    // fail-closed reading is safe. (`git stash push -m "wip on main"` with no
    // option in front is not read as a push.) An alias or autocorrect setting
    // makes the command a push candidate whatever it says.
    const later = words.indexOf("push", i);
    const reads = later >= 0 && (!afterOptionOnly || i > gitAt + 1);
    if (!reads)
      return risky
        ? { dirs, elsewhere, everyBranch: false, risky, refspecs: [] }
        : null;
    i = later;
  }

  let everyBranch = false;
  const positional = [];
  const args = withoutRedirections(words.slice(i + 1));
  for (let k = 0; k < args.length; k++) {
    const a = args[k];
    if (a === "--") {
      positional.push(...args.slice(k + 1));
      break;
    }
    // The newline-only reading leaves a standalone && || ; | & word in the
    // words, because it may sit inside a quoted option value. Once the push has
    // a remote and a refspec such a word ends it; before that (a destination
    // may still follow the value) it does not.
    if (standaloneEnds && SEGMENT_WORDS.has(a) && positional.length >= 2) break;
    if (!a.startsWith("-")) {
      positional.push(a);
    } else if (isEveryBranchOption(a)) {
      everyBranch = true;
    } else if (takesNextWord(a, subtree)) {
      k++;
    }
  }
  // The first positional word is the remote, whether or not --repo is given
  // (git reads it the same way).
  const refspecs = positional.slice(1);
  // {a,b} expands to two refspecs, one of which may be main.
  risky ||= refspecs.some(r => r.includes("{") && r.includes(","));
  // push.default and remote.*.push choose what a push without a refspec does;
  // a refspec on the command line overrides them.
  risky ||= (configRisk || mapRisk) && refspecs.length === 0;
  // remote.*.push maps a refspec given without a colon (feature -> main); an
  // explicit src:dst overrides it.
  risky ||= mapRisk && refspecs.some(r => !r.includes(":"));
  return { dirs, elsewhere, everyBranch, risky, refspecs };
}

/**
 * Where a refspec lands on the remote: the part after `:`, with `refs/heads/`
 * or `heads/` removed. An empty destination (`:` is a matching push) comes back
 * empty.
 */
function destinationOf(refspec) {
  const spec = refspec.replace(/^\+/, "");
  const colon = spec.indexOf(":");
  return (colon < 0 ? spec : spec.slice(colon + 1)).replace(
    /^(?:refs\/)?heads\//,
    ""
  );
}

const isMain = name => name === "main" || name === "master";

/**
 * The fail-closed reader. Deletes every quote and backslash (so `'ma''in'`
 * reads `main`, and an apostrophe in a comment or a heredoc hides nothing),
 * ends a segment at `;` `&` `|` newline `)` `(` and a backtick, and ends a word
 * at `<` and `>`. Braces are ordinary characters, so `{feature,main}` stays one
 * word.
 *
 * Three switches make the caller read the text more than one way:
 * - `join`: each backtick becomes `$`, `(` becomes a space and `)` is deleted,
 *   so a substitution joins the words around it. `git push origin `echo main``
 *   reads `git push origin $echo main$`, whose destination contains `$`;
 *   "Never `git push`" reads "Never $git push$".
 * - `hashCuts`: a word-initial `#` ends the segment (a comment, or a quoted `#`
 *   the deleted quotes no longer protect). Scanning goes on, on the same line.
 *   Without it a quoted `#` inside the push's own arguments (`--push-option
 *   "#ci"`) stays a word.
 * - `newlineOnly`: only a newline ends a segment, so a quoted option value that
 *   holds `;`, `|` or `&` (`-o "A=1;B=2"`, `-o "Fix A & B"`, `-c
 *   credential.helper='!f() { ...; }; f'`) stays inside its push command. A
 *   standalone `&&` `||` `;` `|` `&` word still ends the push's arguments once
 *   it has a remote and a refspec (`parseGit`), so `git push origin feature &&
 *   echo main` passes. Every other rule is the same.
 * - each segment comes back three ways: `words` with every redirection and its
 *   target dropped, `withTargets` with the targets kept (a quoted `>` the
 *   deleted quotes no longer protect would otherwise swallow the next word), and
 *   `head`, the words before the first redirection (a quoted target with a
 *   space, `> "a b"`, would otherwise leave its second half as a refspec).
 */
function looseSegments(command, join, hashCuts, newlineOnly = false) {
  let text = command
    // A backslash joins the next line only after an odd run of backslashes.
    .replace(/(\\+)\n/g, (run, slashes) =>
      slashes.length % 2 === 1 ? slashes.slice(1) : run
    )
    .replace(/['"\\]/g, "");
  if (join)
    text = text
      .replace(/`/g, () => "$")
      .replace(/\(/g, " ")
      .replace(/\)/g, "");
  const segments = [];
  let words = [];
  let withTargets = [];
  let head = [];
  let redirected = false; // a redirection has been seen in this segment
  let word = "";
  let target = false; // the next word is a redirection's target
  const endWord = () => {
    if (word !== "") {
      withTargets.push(word);
      if (!redirected) head.push(word);
      if (target) target = false;
      else words.push(word);
      word = "";
    }
  };
  const endSegment = () => {
    endWord();
    if (withTargets.length > 0) segments.push({ words, withTargets, head });
    words = [];
    withTargets = [];
    head = [];
    redirected = false;
    target = false;
  };
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === "<" || c === ">" || (c === "&" && text[i + 1] === ">")) {
      // 2>&1 and {fd}>file: the number or the {name} is not an argument
      if (/^(?:\d+|\{[A-Za-z_]\w*\})$/.test(word)) word = "";
      endWord();
      const operator = /^(?:&>>?|>>|>&|>\||<<<|<<|<&|<>|[<>])/.exec(
        text.slice(i)
      );
      i += operator[0].length - 1;
      target = true;
      redirected = true;
    } else if (
      hashCuts &&
      c === "#" &&
      word === "" &&
      /^[\s;&|()`]?$/.test(text[i - 1] ?? "")
    ) {
      endSegment();
    } else if (c === " " || c === "\t" || c === "\r") {
      endWord();
    } else if (newlineOnly ? c === "\n" : "\n;&|)(`".includes(c)) {
      endSegment();
    } else {
      word += c;
    }
  }
  endSegment();
  return segments;
}

/** Does this simple command (env assignments and wrappers skipped) change the branch? */
function commandChangesBranch(words) {
  let i = 0;
  while (
    i < words.length &&
    (ENV_ASSIGNMENT.test(words[i]) || PREFIX_WORDS.has(words[i]))
  )
    i++;
  return (
    i < words.length && isGitProgram(words[i]) && changesBranch(words, i)
  );
}

/** Words that end a push's arguments in the newline-only reading (see parseGit). */
const SEGMENT_WORDS = new Set(["&&", "||", ";", ";;", "|", "|&", "&"]);

/** Programs whose arguments are text to search, never a command to run. */
const SEARCH_TOOLS = new Set(["grep", "egrep", "fgrep", "rg", "ag"]);
/**
 * `git grep -O<cmd>` and `--open-files-in-pager=<cmd>`, and `rg --pre <cmd>`,
 * run a command, so a search segment that carries one is not skipped.
 */
const SEARCH_RUNS_COMMAND = /^-[A-Za-z]*O|^--open-files-in-pager|^--pre(?:=|$)/;
const searchesText = words =>
  words.length > 0 &&
  (SEARCH_TOOLS.has(basename(words[0])) ||
    (basename(words[0]) === "git" && words[1] === "grep")) &&
  !words.some(w => SEARCH_RUNS_COMMAND.test(w));

/**
 * The words of the command that starts at the marked git word `words[k]`, cut
 * at the first later word that ends with the closing `$` marker (which is
 * stripped). With no closing marker the words are returned whole.
 */
function closeAtMarker(words, k) {
  for (let j = k + 1; j < words.length; j++) {
    if (!words[j].endsWith("$")) continue;
    const closed = words.slice(0, j);
    const last = words[j].replace(/\$+$/, "");
    if (last !== "") closed.push(last);
    return closed;
  }
  return words;
}

/** An option glued to the front of a program's name (a regular expression source). */
const gluedTo = name =>
  new RegExp(`^(?:-[A-Za-z]+|--[A-Za-z][A-Za-z-]*=)(?=${name}$)`, "i");
const GIT_GLUED = gluedTo("git(?:\\.(?:exe|cmd|bat))?");

/**
 * Is words[k] the program that `isProgram` names (git, gh, curl, wget),
 * possibly with something glued to its front: a substitution marker from the
 * joined reading (`x=$git`, `$git`), an option (`-xgit` and `--exec=git` from
 * `git rebase -x'git push'`), as `glued` matches it? `marked` says a `$`
 * marker was stripped.
 */
function programWord(words, k, glued, isProgram) {
  const word = words[k];
  // `!git` is an alias body; the marker is a substitution's `$`.
  const unmarked = word.replace(/^!/, "").replace(/^[^$]*\$+/, "");
  const bare = unmarked.replace(glued, "");
  return {
    found: isProgram(bare),
    marked: unmarked !== word.replace(/^!/, ""),
  };
}

/** The ways the backstop reads a text: [join, hashCuts, newlineOnly] (see looseSegments). */
const LOOSE_READINGS = [true, false].flatMap(hashCuts => [
  [false, hashCuts, false],
  [true, hashCuts, false],
  [false, hashCuts, true],
]);

/**
 * Does this shell line contain a `git push` whose destination is `main` or
 * `master`? Anything that cannot be resolved counts as yes: an unreadable
 * branch, a destination built by the shell (`$BRANCH`), every branch at once.
 * Two readers look (see the header); either one finding a push is enough.
 *
 * @param {string} command
 * @param {(dir: string | undefined) => string | null} currentBranch the branch of the repository at `dir`, or null when it cannot be read
 * @param {string} [cwd] the directory the session runs in; `-C` values are relative to it
 */
export function pushTargetsMain(command, currentBranch, cwd) {
  if (typeof command !== "string") return false;
  const asked = new Map();
  const branchIsMainOrUnknown = dir => {
    if (!asked.has(dir)) {
      let branch;
      try {
        branch = currentBranch(dir);
      } catch {
        branch = null;
      }
      asked.set(dir, branch);
    }
    const branch = asked.get(dir);
    // A detached HEAD reads back as the word HEAD, which is not a branch.
    return (
      typeof branch !== "string" ||
      branch === "" ||
      branch === "HEAD" ||
      isMain(branch)
    );
  };

  /** Does this parsed push go to main, or might it? */
  const reachesMain = (push, changed = false) => {
    if (push.everyBranch || push.risky) return true;
    const dir = push.dirs.length > 0 ? resolve(cwd ?? ".", ...push.dirs) : cwd;
    // An earlier checkout, switch or branch rename makes the branch unknown.
    const here = () => changed || push.elsewhere || branchIsMainOrUnknown(dir);

    if (push.refspecs.length === 0) return here();
    for (const refspec of push.refspecs) {
      const destination = destinationOf(refspec);
      // A destination that is empty (a matching push), a pattern, or built by
      // the shell cannot be shown to avoid main. ? and [ are glob characters
      // and cannot be in a ref name, so reviewing them costs no real push.
      if (
        isMain(destination) ||
        destination === "" ||
        /[*$?[]/.test(destination) ||
        // @{u}, HEAD@{0}, @{-1} name a ref through git's state; {} is xargs's
        destination.includes("@{") ||
        destination.includes("{}")
      )
        return true;
      // HEAD, and its alias @, are the current branch.
      if ((destination === "HEAD" || destination === "@") && here())
        return true;
    }
    return false;
  };

  return shellReadings(command).some(text => readsPushToMain(text, reachesMain));
}

/**
 * The texts both readers read: the command as written, and the command as
 * PowerShell reads it, where a backtick right before a newline (LF or CRLF)
 * continues the line, a backslash is a path separator rather than an escape
 * (`C:\Git\cmd\git.exe`), and a comma separates the elements of an argument
 * array (`Start-Process git -ArgumentList 'push','origin','main'`). Bash reads
 * none of these that way, so the second text is one more reading, never a
 * replacement: it can only add reviews. A comma is split only between quoted
 * elements or when no space follows it, so prose ("git push, never to main")
 * keeps its comma.
 */
function shellReadings(command) {
  const powerShell = command
    .replace(/`\r?\n/g, " ")
    .replace(/\\/g, "/")
    .replace(/(['"])\s*,\s*(?=['"])/g, "$1 ")
    .replace(/,(?=\S)/g, " ");
  return powerShell === command ? [command] : [command, powerShell];
}

/** Do the two readers (see the header) find a push in `command` that reaches main? */
function readsPushToMain(command, reachesMain) {
  // An earlier checkout, switch or branch rename makes the branch unknown for
  // the pushes after it. Commands inside $( ) and backticks are listed last, so
  // a change there counts for every push.
  const commands = simpleCommands(command);
  const nested = commands.nestedFrom ?? commands.length;
  let changed = commands.slice(nested).some(commandChangesBranch);
  for (const [n, words] of commands.entries()) {
    const push = parsePush(words);
    if (push && reachesMain(push, changed)) return true;
    if (n < nested && commandChangesBranch(words)) changed = true;
  }

  // The backstop: the word git anywhere in a segment, not only first. The text
  // is read with a `#` cutting and not cutting; split at backticks and
  // parentheses, joined across them, and split at newlines only; each segment is
  // read with redirection targets dropped, kept, and cut off at the first
  // redirection. Segments are walked in order, so a checkout or switch makes the
  // branch unknown for the pushes after it.
  for (const [join, hashCuts, newlineOnly] of LOOSE_READINGS) {
    const segments = looseSegments(command, join, hashCuts, newlineOnly);
    for (const variant of ["words", "withTargets", "head"]) {
      let changed = false;
      for (const segment of segments) {
        const words = segment[variant];
        // grep "git push" docs: the pattern is data. Only these tools are
        // skipped; echo and anything that executes are not.
        if (searchesText(words)) continue;
        let elsewhere = false;
        for (let k = 0; k < words.length; k++) {
          const assignment = ENV_ASSIGNMENT.exec(words[k]);
          if (assignment && /^GIT_(?:DIR|WORK_TREE)$/.test(assignment[1]))
            elsewhere = true;
          const found = programWord(words, k, GIT_GLUED, isGitProgram);
          if (!found.found) continue;
          // x=`git push origin feature` reads x=$git push origin feature$:
          // the backtick pair's closing marker ends the command, and is not
          // part of the word that carries it.
          const seen = join && found.marked ? closeAtMarker(words, k) : words;
          const push = parseGit(seen, k, elsewhere, true, newlineOnly);
          if (push) {
            // a push fed by xargs takes its destination from the input
            const fed = words.slice(0, k).some(w => basename(w) === "xargs");
            if (fed || reachesMain(push, changed)) return true;
          } else if (changesBranch(seen, k)) {
            changed = true;
          }
        }
      }
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Bash: main moved through the GitHub API (founder ruling, 2026-10-22)
// ---------------------------------------------------------------------------

/** A test of a word's program name: its last path part (either slash), in any letter case. */
const programNamed = name => {
  const re = new RegExp(`^${name}$`, "i");
  return word => re.test(basename(word.replace(/\\/g, "/")));
};
/** The clients whose options the guard reads: [kind, test, glued option]. */
const CLIENTS = [
  ["gh", "gh(?:\\.exe)?"],
  ["curl", "curl(?:\\.exe)?"],
  ["wget", "wget2?(?:\\.exe)?"],
].map(([kind, name]) => [kind, programNamed(name), gluedTo(name)]);
/** A word that may be one of them: the backstop asks this of every word first. */
const MAY_BE_CLIENT = /gh|curl|wget/i;

/**
 * A ref or branch name filled in when the command runs: a variable or a
 * substitution, gh's `{branch}` placeholder (the checked-out branch), a glob,
 * or a value gh reads from a file (`-F branch=@file`). It may be main.
 */
const FILLED_IN_LATER = /[$`{}*?[\]]|^@/;

/**
 * Does this branch or ref name (`main`, `heads/main`, `refs/heads/main`) name
 * main or master, or might it? In any letter case. Something that is not a
 * string, an empty name (no branch: the default branch) and a name filled in
 * later all count. `tags/main` is a tag, and `feature/main` another branch.
 */
function namesMain(ref) {
  if (typeof ref !== "string") return true;
  const name = ref.trim().replace(/^\/+|\/+$/g, "");
  if (name === "" || FILLED_IN_LATER.test(name)) return true;
  const bare = name.replace(/^refs\//i, "").replace(/^heads\//i, "");
  return /^(?:main|master)$/i.test(bare);
}

/**
 * The routes of GitHub's REST API that move a branch, in every way of reading
 * `word`: as written and percent-decoded, with the owner and repository as two
 * path parts or as one (`repos/$GITHUB_REPOSITORY/...`). Path words in any
 * letter case. Each route says what decides whether a write to it moves main:
 *   pulls/<n>/merge, merges        nothing: it is a merge, whatever its base
 *   git/refs/<ref>                 the ref the path names
 *   git/refs                       a new ref, named by the `ref` field
 *   contents/..., merge-upstream   the `branch` field; with none, the default branch
 */
function githubRoutes(word) {
  if (!/repos|%/i.test(word)) return [];
  const texts = new Set([word]);
  try {
    texts.add(decodeURIComponent(word));
  } catch {
    // A malformed escape: the word is read as written.
  }
  const routes = [];
  for (const text of texts) {
    for (const m of text.matchAll(/(?:^|\/)repos\/([^?#\s'"`()<>,;|&]*)/gi)) {
      const parts = m[1].split("/");
      for (const skip of [1, 2]) {
        const route = routeOf(parts.slice(skip));
        if (route !== null) routes.push(route);
      }
    }
  }
  return routes;
}

/** The route of the path parts after `repos/<owner>/<repository>/`, or null. */
function routeOf(parts) {
  const [a = "", b = "", c = ""] = parts.map(p => p.toLowerCase());
  if ((a === "pulls" && c === "merge") || a === "merges")
    return { always: true };
  if (a === "contents" || a === "merge-upstream") return { field: "branch" };
  if (a === "git" && b === "refs") {
    const ref = parts.slice(2).join("/").replace(/\/+$/, "");
    return ref === "" ? { field: "ref" } : { ref };
  }
  return null;
}

/**
 * Does a write to this route move main? `fields` are gh api's -f/-F fields as
 * {key, value}, or null when the body cannot be read. A field counts by its
 * exact key (GitHub ignores `Branch`); gh sends the last of two, and either may
 * be main.
 */
function routeMovesMain(route, fields) {
  if (route.always) return true;
  if (route.ref !== undefined) return namesMain(route.ref);
  if (fields === null) return true;
  const named = fields.filter(f => f.key === route.field);
  return named.length === 0 || named.some(f => namesMain(f.value));
}

/**
 * GraphQL mutations that merge a pull request or create, move or delete a ref.
 * Their arguments are IDs and nested inputs the guard does not read, so each
 * counts whatever it names. They are looked for in the whole command, so a
 * query written over several lines (separate segments to the backstop) is
 * found.
 */
const BRANCH_MUTATION =
  /(?<![A-Za-z0-9_])(?:mergePullRequest|enablePullRequestAutoMerge|enqueuePullRequest|mergeBranch|createCommitOnBranch|createRef|updateRefs?|deleteRef)(?![A-Za-z0-9_])/i;
/** gh api's GraphQL endpoint (`graphql`), or a URL that ends in /graphql. */
const GRAPHQL_ENDPOINT = /^graphql$|\/graphql(?:[?#]|$)/i;
/** GitHub's GraphQL URL as any program may spell it, inside a word too. */
const GRAPHQL_URL = /(?:api\.github\.com|\/api)\/graphql(?![A-Za-z0-9_-])/i;
/** A URL of GitHub's REST API: api.github.com, GitHub Enterprise's /api/v3/, or Actions' GITHUB_API_URL. */
const GITHUB_API_HOST = /api\.github\.com|\/api\/v3\/|GITHUB_API_URL/i;

const isReadMethod = method => /^(?:get|head)$/i.test(method);
/**
 * Is the request a write? With a method given, unless every one given is GET
 * or HEAD (the last wins, and `-X $M` is not a read); with none, when it sends
 * a body.
 */
const writes = (methods, body) =>
  methods.length > 0 ? !methods.every(isReadMethod) : body;

/**
 * The newline-only reading keeps a standalone `&&` `;` `|` word, because one
 * may sit inside a quoted value (see parseGit). Once a word naming a route or
 * GraphQL has been read, such a word ends the command, so `gh api <route> &&
 * rm -f x` does not read `-f x` as a field; before one, it does not.
 */
function upToNextCommand(args) {
  let routed = false;
  for (let k = 0; k < args.length; k++) {
    if (routed && SEGMENT_WORDS.has(args[k])) return args.slice(0, k);
    if (GRAPHQL_ENDPOINT.test(args[k]) || githubRoutes(args[k]).length > 0)
      routed = true;
  }
  return args;
}

/**
 * gh's command words and where they sit in `args`, read two ways: cobra lets
 * an option written before them take the next word as its value or not,
 * depending on the option (`gh -R o/r pr merge`, `gh pr -R o/r merge`).
 */
function ghCommandReadings(args) {
  return [false, true].map(optionsTakeValues => {
    const at = [];
    for (let k = 0; k < args.length && at.length < 2; k++) {
      if (args[k].startsWith("-") && args[k].length > 1) {
        if (optionsTakeValues && !args[k].includes("=")) k++;
      } else {
        at.push(k);
      }
    }
    return at;
  });
}

/**
 * Does the gh command whose word gh is `words[at]` move main? `gh pr merge` in
 * any form, `gh api` (ghApiMovesMain), `gh repo sync` (repoSyncMovesMain).
 * `text` is the whole command, for GraphQL.
 */
function ghMovesMain(words, at, text) {
  const args = withoutRedirections(words.slice(at + 1));
  for (const [first, second] of ghCommandReadings(args)) {
    const one = (args[first] ?? "").toLowerCase();
    const two = (args[second] ?? "").toLowerCase();
    if (one === "pr" && two === "merge") return true;
    if (
      one === "api" &&
      ghApiMovesMain(args.filter((_, k) => k !== first), text)
    )
      return true;
    if (
      one === "repo" &&
      two === "sync" &&
      repoSyncMovesMain(args.filter((_, k) => k !== first && k !== second))
    )
      return true;
  }
  return false;
}

/** gh api's options that take a value: the short letters, and each long name with its letter. */
const GH_API_SHORT_VALUES = "XfFHpqt";
const GH_API_LONG_VALUES = new Map([
  ["--method", "X"],
  ["--raw-field", "f"],
  ["--field", "F"],
  ["--input", "input"],
  ["--header", "H"],
  ["--hostname", "hostname"],
  ["--jq", "q"],
  ["--template", "t"],
  ["--preview", "p"],
  ["--cache", "cache"],
]);

/** The methods, fields ({key, value}) and --input of gh api's words. */
function ghApiOptions(args) {
  const methods = [];
  const fields = [];
  let input = false;
  const take = (option, value) => {
    if (option === "X") {
      methods.push(value);
    } else if (option === "f" || option === "F") {
      const eq = value.indexOf("=");
      fields.push(
        eq < 0
          ? { key: value, value: undefined }
          : { key: value.slice(0, eq), value: value.slice(eq + 1) }
      );
    } else if (option === "input") {
      input = true;
    }
  };
  for (let k = 0; k < args.length; k++) {
    const a = args[k];
    if (a === "--") break;
    const long = /^(--[A-Za-z-]+)(?:=([\s\S]*))?$/.exec(a);
    if (long) {
      // Any other long option is a switch.
      if (GH_API_LONG_VALUES.has(long[1]))
        take(GH_API_LONG_VALUES.get(long[1]), long[2] ?? args[++k] ?? "");
    } else if (/^-[A-Za-z]/.test(a)) {
      // Switches (-i), then at most one option, whose value is the rest of the
      // word or the next word: -iX PUT, -XPUT, -X=PUT, -fkey=value.
      for (let j = 1; j < a.length; j++) {
        if (!GH_API_SHORT_VALUES.includes(a[j])) continue;
        const rest = a.slice(j + 1).replace(/^=/, "");
        take(a[j], rest !== "" ? rest : (args[++k] ?? ""));
        break;
      }
    }
  }
  return { methods, fields, input };
}

/**
 * Does this gh api command (its words without the word api) move main? A write
 * (a method other than GET or HEAD; with none, a field or --input, which gh
 * sends as a POST) to a route that moves main, read with its fields; with
 * --input the body is the file, and gh puts the fields in the query string.
 * GraphQL is a POST: a mutation the command spells, or a query read from a file.
 */
function ghApiMovesMain(args, text) {
  const words = upToNextCommand(args);
  const { methods, fields, input } = ghApiOptions(words);
  if (
    words.some(w => GRAPHQL_ENDPOINT.test(w)) &&
    (BRANCH_MUTATION.test(text) ||
      input ||
      fields.some(f => f.key === "query" && /^@/.test(f.value ?? "")))
  )
    return true;
  if (!writes(methods, fields.length > 0 || input)) return false;
  const body = input ? null : fields;
  return words.some(w => githubRoutes(w).some(r => routeMovesMain(r, body)));
}

/**
 * gh repo sync <repository> moves that repository's branch on GitHub to its
 * upstream's: the default branch, or the one --branch names. With no
 * repository it syncs the local clone, and nothing on GitHub moves.
 */
function repoSyncMovesMain(args) {
  const branches = [];
  let remote = false;
  for (let k = 0; k < args.length; k++) {
    const a = args[k];
    if (SEGMENT_WORDS.has(a)) break;
    const option =
      /^(?:--(branch|source)(?:=([\s\S]*))?|-([bs])([\s\S]*))$/.exec(a);
    if (option) {
      const value =
        option[2] ?? (option[4] ? option[4].replace(/^=/, "") : args[++k]);
      if (option[1] === "branch" || option[3] === "b") branches.push(value);
    } else if (!a.startsWith("-")) {
      remote = true;
    }
  }
  return remote && (branches.length === 0 || branches.some(namesMain));
}

/** curl's short options that take a value, in the rest of the word or the next word. */
const CURL_SHORT_VALUES = "AbcCdDeEFHKmoPQrtTuUwxXyYz";
/** curl's and wget's long options that send a body. */
const BODY_OPTIONS =
  /^--(?:data(?:-ascii|-binary|-raw|-urlencode)?|json|form(?:-string)?|(?:post|body)-(?:data|file))$/;
/**
 * PowerShell's names for the method and the body, or a prefix of one (Windows
 * PowerShell runs curl and wget as Invoke-WebRequest: `curl -Method Put`).
 */
const isPowerShellMethod = name =>
  name.length >= 2 &&
  ("method".startsWith(name) || "custommethod".startsWith(name));
const isPowerShellBody = name =>
  name.length >= 2 &&
  ("body".startsWith(name) || (name.length >= 3 && "infile".startsWith(name)));

/**
 * Does this curl or wget command (its words after the program) write to a
 * route that moves main? The guard does not read the body they send, so a
 * route that depends on a field counts whatever it names. GraphQL: a mutation
 * the command spells, or a body read from a file.
 */
function httpClientMovesMain(args, isWget, text) {
  const words = upToNextCommand(args);
  const methods = [];
  let body = false;
  let get = false; // -G: the body goes into the query string
  let fromFile = false;
  // -T is an upload, a PUT; -K reads a config file, which can set the method
  // and the URL. Either is a write whatever else the command says.
  let unknown = false;
  const send = value => {
    body = true;
    if (/^[@<]|=[@<]/.test(value)) fromFile = true;
  };
  for (let k = 0; k < words.length; k++) {
    const a = words[k];
    const ps = /^-([A-Za-z]{2,})(?::([\s\S]*))?$/.exec(a);
    if (ps && isPowerShellMethod(ps[1].toLowerCase())) {
      methods.push(ps[2] ?? words[++k] ?? "");
      continue;
    }
    if (ps && isPowerShellBody(ps[1].toLowerCase())) {
      body = true;
      fromFile = true;
      continue;
    }
    const long = /^(--[A-Za-z-]+)(?:=([\s\S]*))?$/.exec(a);
    if (long) {
      const value = () => long[2] ?? words[++k] ?? "";
      if (long[1] === "--request" || long[1] === "--method") {
        methods.push(value());
      } else if (BODY_OPTIONS.test(long[1])) {
        const v = value();
        send(long[1].endsWith("-file") ? `@${v}` : v);
      } else if (long[1] === "--upload-file") {
        unknown = true;
      } else if (long[1] === "--get") {
        get = true;
      } else if (long[1] === "--head") {
        methods.push("HEAD");
      } else if (long[1] === "--config") {
        unknown = true;
      }
    } else if (!isWget && /^-[A-Za-z0-9#]/.test(a)) {
      // A curl cluster: switches (-s, -S, -G, -I), then at most one option,
      // whose value is the rest of the word or the next word.
      for (let j = 1; j < a.length; j++) {
        const c = a[j];
        if (c === "G") get = true;
        else if (c === "I") methods.push("HEAD");
        if (!CURL_SHORT_VALUES.includes(c)) continue;
        const rest = a.slice(j + 1).replace(/^=/, "");
        const value = rest !== "" ? rest : (words[++k] ?? "");
        if (c === "X") methods.push(value);
        else if (c === "d" || c === "F") send(value);
        else if (c === "T" || c === "K") unknown = true;
        break;
      }
    }
  }
  if (!unknown && !writes(methods, body && !get)) return false;
  if (
    words.some(w => GRAPHQL_ENDPOINT.test(w)) &&
    (unknown || fromFile || BRANCH_MUTATION.test(text))
  )
    return true;
  return words.some(w => githubRoutes(w).some(r => routeMovesMain(r, null)));
}

/**
 * Does this word spell a GitHub API URL on a route that moves main, for a
 * program whose options the guard does not read? Such a program may write, so
 * the URL is enough. A GraphQL URL counts with a mutation the command spells.
 */
function spellsGithubWrite(word, text) {
  if (GRAPHQL_URL.test(word) && BRANCH_MUTATION.test(text)) return true;
  return (
    GITHUB_API_HOST.test(word) &&
    githubRoutes(word).some(r => routeMovesMain(r, null))
  );
}

/** Does this client command (its program at `words[at]`) move main? */
function clientMovesMain(kind, words, at, text) {
  if (kind === "gh") return ghMovesMain(words, at, text);
  return httpClientMovesMain(
    withoutRedirections(words.slice(at + 1)),
    kind === "wget",
    text
  );
}

/**
 * Does this shell command move main or master through the GitHub API, or might
 * it? The two readers of a push (see the header) read it, as written and as
 * PowerShell reads it; either one finding a move is enough.
 *
 * @param {string} command
 */
export function githubMovesMain(command) {
  if (typeof command !== "string") return false;
  return shellReadings(command).some(readsGithubMove);
}

/** Do the two readers find a move of main through the GitHub API in `text`? */
function readsGithubMove(text) {
  // The quote-aware reader: the program in command position decides. (A URL in
  // an env assignment in front, `URL=... curl -X PUT $URL`, is the backstop's:
  // no client stands before it in its segment.)
  for (const words of simpleCommands(text)) {
    let i = 0;
    while (
      i < words.length &&
      (ENV_ASSIGNMENT.test(words[i]) || PREFIX_WORDS.has(words[i]))
    )
      i++;
    const command = words.slice(i);
    if (command.length === 0 || searchesText(command)) continue;
    const client = CLIENTS.find(([, isProgram]) => isProgram(command[0]));
    if (
      client
        ? clientMovesMain(client[0], command, 0, text)
        : command.some(w => spellsGithubWrite(w, text))
    )
      return true;
  }

  // The backstop: gh, curl or wget anywhere in a segment, read from there; a
  // GitHub URL with none of them in front of it in its segment counts by
  // itself.
  for (const [join, hashCuts, newlineOnly] of LOOSE_READINGS) {
    for (const segment of looseSegments(text, join, hashCuts, newlineOnly)) {
      for (const variant of ["words", "withTargets", "head"]) {
        const words = segment[variant];
        if (searchesText(words)) continue;
        let client = false;
        for (let k = 0; k < words.length; k++) {
          let found = null;
          if (MAY_BE_CLIENT.test(words[k])) {
            for (const [kind, isProgram, glued] of CLIENTS) {
              const word = programWord(words, k, glued, isProgram);
              if (word.found) {
                found = { kind, marked: word.marked };
                break;
              }
            }
          }
          if (found) {
            client = true;
            const seen = join && found.marked ? closeAtMarker(words, k) : words;
            if (clientMovesMain(found.kind, seen, k, text)) return true;
          } else if (!client && spellsGithubWrite(words[k], text)) {
            return true;
          }
        }
      }
    }
  }
  return false;
}
