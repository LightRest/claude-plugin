---
name: verify-record
description: Use when someone shows you a LightRest Human Review Record and wants to know whether it holds up: an HOC-… credential id, a lightrest.net/verify link, or a credential JSON file, or a document that cites an OR-… record id with one of those beside it. Checks the record through the LightRest verifier, which needs no account, and reports what the record proves and what it does not.
---

# Check a LightRest record

The `lightrest-verify` MCP server has one tool, `verify_record`. It checks a Human Review Record credential issued by LightRest: its signature, whether it was revoked, and its validity window. It needs no LightRest account and changes no record; LightRest logs the check.

## Find what to check

- An `HOC-…` id: pass it as `credentialId`.
- A link of the form `https://lightrest.net/verify/HOC-…`: pass the `HOC-…` part as `credentialId`.
- A credential JSON object, pasted or in a file: read it and pass the whole object as `credential`, unchanged. Do not reformat, trim or re-key it: any change breaks the signature.
- An `OR-…` record id alone cannot be checked: it names the record, not the credential. Ask for the `HOC-…` id or the verify link that came with it.

## Report the result

Read `structuredContent` and report it as returned.

- `verified: true`: say "Verified", give the `summary`, then list `proves` and `doesNotProve` exactly as returned.
- `verified: false` with `unavailable: true`: the check did not finish because LightRest could not read its revocation list. Say so and suggest trying again later. Do not call the record valid or invalid.
- `notIssuedByLightRest: true`: say the credential was not issued by LightRest, so this tool says nothing about it.
- Any other `verified: false`: say "Not verified", give the `summary` and the `errors`. A record that did not verify proves nothing.

## What you may say

Say "verified" only about a credential for which `verify_record` returned `verified: true` in this conversation. Never say a record shows that a human verified the output, that the content is correct, or that the reviewer is licensed. Answer "what does this prove" from the tool's `proves` and `doesNotProve` lists and from the list below, not from memory.

The check covers the credential as issued. It does not recompute the organisation's audit chain, which a relying party does not receive.

## What a record does not prove

<!-- DOES_NOT_PROVE:begin (written by scripts/sync-mcp-listing.ts; do not edit) -->
- That the AI authored the text. The credential says who supplied the output: the reviewer, or a connected system before review. Neither proves which model wrote it.
- That the human cognitively engaged. Timing and rationale-originality checks make rubber-stamping harder, not impossible. A reviewer who approves without reading still produces a valid record.
- That an unchanged approval equals a heavy edit. With no diff, it rests on the rationale alone. The record marks it attestation-only, the weaker of the two weights we issue.
- That a witness read the work. A witness attests receipt and time. They were not shown the content.
- That the reviewer is licensed under the mandate the record names. We never verify a licence against an issuing authority. A record may name a statute its reviewer holds no licence under, and it says so on its face.
- That we know who the witness is. Enrolling proves control of the email address named for this record. We verify nothing beyond that address.
- That the witness is a different person from the reviewer. The refusal compares accounts, not people. One person controlling two email addresses can be both.
- That the action was executed as authorised. The record seals the authorisation; we do not observe execution.
<!-- DOES_NOT_PROVE:end -->
