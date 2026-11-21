# LightRest for Claude Code

A person reviews and seals what your agent produced. This plugin connects Claude Code to the LightRest MCP server at `https://lightrest.net/mcp`, adds two skills that say when and how to ask for a review, one command, and an action guard that holds chosen production calls until a person authorises them.

Docs for the server itself: https://lightrest.net/developers/mcp

## Install

```
/plugin marketplace add LightRest/claude-plugin
/plugin install lightrest@lightrest
```

On install Claude Code asks for your **LightRest agent key**: an `lr_agt_` key from https://lightrest.net/app/agents. It is stored in your credential store, sent as the bearer on every call to `https://lightrest.net/mcp`, and never written to `settings.json`.

LightRest's MCP server also accepts OAuth sign-in, with no key to paste. This plugin uses an agent key.

## What it adds

| Component | What it does |
|---|---|
| MCP server `lightrest` | `request_human_review`, `request_action_review`, `get_review`, `verify_record` |
| Skill `human-review` | When to request a review of an output, how to wait, what to say afterwards, what a record does not prove |
| Skill `action-review` | The same for a proposed tool call: execute exactly what was authorised, or nothing |
| Command `/lightrest:review [file]` | Sends the file, or the last assistant message, for review as a `draft` |
| Hook `hooks/hooks.json` (action guard) | Before a guarded call runs, asks your reviewer to authorise it; see [Action guard](#action-guard) |

## Action guard

A hook that holds a production call until a person has authorised that exact call with their passkey. Every approval leaves a sealed Human Review Record. The guard is a seatbelt against an agent's mistakes, not a security boundary: a shell command can always be phrased a way the guard does not read, and an agent with file access could edit the installed script. It does not stop a malicious agent. Claude Code 2.1.295 or later is required (`onFailure`).

The hook runs before every Bash, PowerShell, Monitor and MCP tool call (`hooks/hooks.json`, matcher `Bash|PowerShell|Monitor|mcp__.*`). A call the policy does not guard is answered in milliseconds with no output and no network, and Claude Code's normal permission flow continues.

### What it guards

A tool is matched case-insensitively on its last segment, so the same rules cover a claude.ai connector and a local server. A server is guarded when its name holds `supabase`, `railway`, `stripe` or `github` as a word set off by `-` or `_`: `supabase-prod`, `stripe_live`, `claude_ai_Supabase` and `plugin_engineering_github` are guarded, `notstripe` and `stripey` are not. A name cannot say what a server does, so this errs towards review. Inside a guarded server, a tool the policy does not list waits for review, so a new write tool is guarded before anyone lists it. GitHub is the exception: most of its tools (issues, comments, pull requests, reads) cannot move a branch, so there a tool the policy does not list passes.

| Server | Refused (never sent) | Waits for review | Passes |
|---|---|---|---|
| Supabase | `create_edge_function_secret`; any `execute_sql` or `apply_migration` that calls `vault.create_secret` or `vault.update_secret` | `apply_migration`; `execute_sql` unless plainly read-only; branch merge, reset, rebase and delete; project pause, restore and create; `deploy_edge_function`; any tool not listed | `list_*`, `get_*`, `search_docs`, `generate_typescript_types`, `query_logs`, read-only `execute_sql` |
| Railway | `set-variables`, `list-variables`, `get-bucket-credentials`, `reset-bucket-credentials` | every create, update, delete, deploy, redeploy, restart, accept, connect, generate, feature or beta toggle, purge and `railway-agent`; any tool not listed | `list-*`, `get-*` (except credentials), `describe-*`, `*-status`, `search-*`, `fetch-docs`, `whoami`, `http-*` |
| Stripe | none | anything that is not a read; any tool not listed | `list_*`, `retrieve_*`, `search_*`, `get_*`, `fetch*` |
| GitHub | none | `merge_pull_request` and `enable_pr_auto_merge`, always (their arguments do not name the base branch); `push_files`, `create_or_update_file` and `delete_file` when `branch` is `main` or `master`, or is left out (the default branch) | every other tool, a new one included |
| Bash, PowerShell, Monitor | none | `git push` in the command whose destination resolves to `main` or `master`: an explicit refspec (`main`, `HEAD:main`, `+main`, `refs/heads/main`), `-C <dir>` and `--git-dir` forms, `--force` and `-f`, and a bare `git push` or `git push <remote>` while the checked-out branch is `main` (if the branch cannot be read, the push waits for review); `main` moved through the GitHub API (below) | everything else |

Read-only SQL is one statement that begins with `SELECT`, `WITH` or `EXPLAIN` (not `EXPLAIN ANALYZE`) and contains no write, DDL, `GRANT`, `COPY`, `CALL`, `DO`, `SET` or `INTO`, after comments and string literals are removed. A function call the guard cannot vouch for (a schema-qualified call outside `pg_catalog` and `information_schema`, a `pg_*` call off the read list, `cron.*`, `net.*`, `dblink*`, `set_config`, `setval`, `nextval`, `lo_*`, `*_to_xml`, `http*`, `pg_notify`, and PostGIS's table-changing functions such as `AddGeometryColumn` and `DropGeometryTable`) and any reference to the `vault` schema wait for review.

A merge or a write that moves `main` through the GitHub API waits like a push to it. In a shell command that is:

- `gh pr merge`, in any form (`--auto` included);
- a `gh api` write (a method other than `GET` or `HEAD`; with none, a `-f`, `-F` or `--input`, which gh sends as a `POST`) to `repos/<owner>/<repo>/pulls/<n>/merge` or `/merges`; to `/git/refs` naming `main` or `master`, in the path or in the `ref` field of a new ref; or to `/contents/...` or `/merge-upstream` unless a `branch` field names another branch (with `--input` the body is a file the guard does not read, so the call waits);
- `gh api graphql` with a mutation that merges or moves a ref (`mergePullRequest`, `enablePullRequestAutoMerge`, `enqueuePullRequest`, `mergeBranch`, `createRef`, `updateRef`, `updateRefs`, `deleteRef`, `createCommitOnBranch`), or a query read from a file;
- `gh repo sync <repo>` unless `--branch` names another branch;
- a `curl` or `wget` write to those routes, Windows PowerShell's `-Method` included; their body is not read, so a file written through them waits whatever branch it names;
- any other command that spells an `api.github.com` (or `/api/v3/`) URL on those routes, such as `Invoke-RestMethod`, `http` or a `python -c` line: the guard does not read its options, so the URL is enough.

A branch name filled in when the command runs (`$BRANCH`, gh's `{branch}`, `-F branch=@file`) counts as `main`, and names are compared in any letter case. These pass: `gh api` with no method or with `GET`, `gh pr view`, `list`, `checks`, `diff` and `create`, a `gh api` write to any other route, and a `curl` that sends nothing.

A shell command passes when two readers of the text agree: one tracks shell quoting, the other ignores quotes and looks for `git`, `gh`, `curl` and `wget` anywhere. The cost is accepted: a commit message, heredoc or `echo` that spells out a push to `main`, `gh pr merge` or such a URL asks for a passkey. Bash, PowerShell and Monitor are read the same way: as written, and again as PowerShell reads it (a backtick at the end of a line continues it, a backslash separates a path, a comma separates an argument array, as in `Start-Process git -ArgumentList 'push','origin','main'`). `git.exe`, `git.cmd` and a full path to either count as git, in any letter case. A Monitor that watches a WebSocket has no command and passes. For these tools the guard sends, hashes and compares the `command` alone: the description, timeout and background flag are left out, so a retry worded differently still finds its seal, and a command your reviewer edits runs with those fields as the agent set them.

### What happens to a call that waits

1. A call that carries a secret (`sk_live_`, `sk_test_`, `rk_live_`, `whsec_`, `lr_agt_`, a `Bearer` token, a PEM private key, a JWT, a `postgres://user:password@` URL) is never sent. The agent is told to remove it and call again. A refused call is never sent either; the agent is told to ask you to do it in the provider's dashboard.
2. The guard sends the proposed call to LightRest as `request_action_review` (to `https://lightrest.net/mcp`, like the review tools) and polls `get_review`. Your org owner gets the usual capture notification, opens the review link and seals with a passkey on lightrest.net.
3. A seal authorises that exact call for 15 minutes after sealing. A seal older than that is spent: the guard asks for a new review in the same call.
4. If the reviewer edits the call before sealing, the edited call runs and the agent is told which arguments changed. If the reviewer authorises a different tool, or nothing, the call is denied.
5. If nobody has sealed within about 9 minutes, the call is denied with the review link; call it again after the seal. A review that expired unsealed is asked for again within the same call, up to 3 times, and then the call is denied and the agent asks you. A discarded review is final for that call in that session: the reviewer turned it down, so the agent asks you.

If the server cannot be reached or answers an error, the call is denied and the reason says why. The monthly seal quota is enforced when your reviewer seals, not when the guard asks, so a call over quota ends at "Waiting for authorisation" while the reviewer sees the refusal. If the script itself crashes or times out, Claude Code blocks the call (`onFailure: "block"`).

### Set the key

The guard uses the plugin's `api_key` option, or the `LIGHTREST_AGENT_KEY` environment variable when the option is empty. Issue an `lr_agt_` key at https://lightrest.net/app/agents. With neither set, a call that needs review is denied with "Set your LightRest agent key"; calls that pass are unaffected. The key can request and read reviews in your org and can never seal one. In a cloud session the model can read an environment variable, so treat that key accordingly. Sealing counts against your org's monthly seal quota.

### Accepted limits

A seatbelt reads text, and these it does not read:

- git reached through a variable, an alias, a function or `eval`
- a PowerShell argument array of bare words with a space after each comma (`-ArgumentList push, origin, main`), whose comma reads like prose
- `export GIT_DIR` before a push
- a bare `git push` after `cd <repo-on-main> &&`, where the guard reads the branch from the session's directory, not the directory the command moved to
- `git fetch . feature:main`, which moves `main` without a push
- `gh` reached through an alias or an extension
- the GitHub API reached through a variable that holds the whole endpoint or URL (`curl -X PUT "$URL"`) or from a script file, by a program other than `gh`, `curl` and `wget` at a URL that does not name GitHub's API host, and a GraphQL mutation the command does not spell out
- a workflow that pushes to `main` itself, started with `gh workflow run` or an MCP tool such as `actions_run_trigger`
- unqualified user-defined SQL functions, and extension functions called without their schema (Supabase puts its `extensions` schema on the search path) other than the PostGIS ones the guard names
- extglob destinations
- a secret with no recognisable shape and no secret-like name
- a tool that runs a shell command and is outside the matcher: the guard covers Bash, PowerShell and Monitor in Claude Code 2.1.306, and a shell tool added later is not read until the matcher and policy name it
- at most 4 authorisations of one identical call per session (the first and 3 asked again after a seal went stale); after that the guard denies until a new session

## Data

The action guard sends each guarded call it holds (the tool name and its arguments) to LightRest for review, and nothing for calls it passes; a call carrying a secret is never sent. Content you send for review goes to LightRest over the same endpoint the server documents, and nowhere else. No telemetry. Privacy policy: https://lightrest.net/legal/privacy-policy

## Maintainers

Source of truth is `integrations/claude-plugin` in the LightRest repository; `scripts/sync-claude-plugin.sh` copies it into this public repository. The skills' "what the record does not prove" list is written by `scripts/sync-mcp-listing.ts` from the shared claims module, and a test fails if it drifts.

Validate before publishing (Claude Code v2.1.281 or later):

```
claude plugin validate --strict integrations/claude-plugin
claude plugin validate --strict integrations/claude-plugin-marketplace
```

Transcript, 2026-09-30, Claude Code 2.1.285, both directories:

```
Validating plugin manifest: integrations/claude-plugin/.claude-plugin/plugin.json
✔ Validation passed
Validating marketplace manifest: <marketplace root>/.claude-plugin/marketplace.json
✔ Validation passed
```
