# LightRest record check for Claude Code

Check a LightRest review record. No account needed.

Someone hands you a LightRest Human Review Record: an `HOC-…` id, a `lightrest.net/verify` link, or a credential JSON file. This plugin lets Claude check it through LightRest's public verifier at `https://lightrest.net/mcp/verify` and tell you what the record proves and what it does not. It sends no key and needs no sign-up.

For requesting reviews, install the `lightrest` plugin from the same marketplace instead; it includes this check.

## Install

```
/plugin marketplace add LightRest/claude-plugin
/plugin install lightrest-verify@lightrest
```

## What it adds

| Component | What it does |
|---|---|
| MCP server `lightrest-verify` | `verify_record`: signature, revocation and validity window of a LightRest credential |
| Skill `verify-record` | What to pass, how to report each result, and what a record does not prove |
| Command `/lightrest-verify:verify <id, link or file>` | Checks one record |

## What the check covers

`verify_record` checks the credential as issued: its signature, whether LightRest revoked it, and its validity window. It does not recompute the issuing organisation's audit chain, which only that organisation, or someone it hands its audit bundle to, can do. The full list of what a record does not prove is in `skills/verify-record/SKILL.md`.

## Data

The plugin sends the id or credential you ask it to check, and nothing else, to `lightrest.net`. LightRest logs each check of an id it holds, or of a credential, as a verification event (privacy policy §3); a check by id of a credential that is not revoked may also add to that record's count of checks. An id LightRest does not hold is not logged. Privacy policy: https://lightrest.net/legal/privacy-policy

## Support

michael@lightrest.net. Docs: https://lightrest.net/developers/mcp

## License

Apache-2.0
