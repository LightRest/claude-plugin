---
name: action-review
description: Use before executing a tool call that is irreversible, spends money, sends a message outside the organization, changes production data, or that the user asked to have authorised by a person. Sends the proposed call (tool name and arguments) to a reviewer through the LightRest MCP server, waits, and executes exactly what they authorised, or nothing.
---

# Request authorisation for an action

`request_action_review` sends the tool call you intend to make, not its result, to a person in the user's LightRest organization. They can authorise it as proposed, edit its arguments, or refuse it, and seal that decision with their passkey. What they authorised is what you may execute.

## When to request

- The call is irreversible, moves money, sends something outside the organization, or changes production data.
- The user asked for a person to approve actions of this kind.
- You are unsure whether the call is what the user meant.

Never for read-only calls, and never as a way to make a person responsible for a call you could have checked yourself.

## How

1. Call `request_action_review` with `tool` (the exact tool name), `arguments` (the exact object you would pass), `aiSystem`, an `externalRef` for the piece of work, and optionally `expiresInMinutes` (default 60, at most 24 hours). It returns `captureId`, `reviewUrl`, and `expiresAt`.
   Do not include credentials or secrets in `arguments`: the reviewer reads them, and they are kept, by LightRest by default, or in the proxy's store on this machine under local custody (next paragraph).
   Send `tool` and `arguments` the same way when the organisation keeps content local: if the server runs through `@lightrest/mcp` with `LIGHTREST_CONTENT_CUSTODY=local`, the proxy stores the call on this machine and sends only its digest. When that review is sealed, the paths of the arguments that changed, object keys included, are published in the credential, so keep sensitive data out of argument keys.
2. Wait on the task if the client supports MCP Tasks; otherwise poll `get_review` no more often than every 15 seconds, backing off to 60 seconds, and stop at `expiresAt`.

## While waiting

Tell the user the `reviewUrl` and that a member of their organization must open it. Do not execute the call, a narrower version of it, or a substitute.

## After

`get_review` returns an `action` object with `proposedTool` and `authorised`:

- Execute exactly `authorised`: that tool, those arguments, nothing added.
- If `authorised` is `null`, do not execute anything. Report the reviewer's rationale to the user.
- Never re-add arguments the reviewer removed, and never change the tool they authorised for one you prefer.
- If the review expired before a decision, do not execute. Ask the user whether to request again.
- Local custody: if the record is sealed but the text says the authorised text has not reached this machine's store, `authorised` is `null` until it does. Do not execute; keep polling `get_review`.

Quote the record id and the `verifyUrl` wherever you report what was done.

## What you may say

Say: "A human authorised this action: <record id>, <verifyUrl>." Say "verified" about the record only after `verify_record` has returned `verified: true` for it.

## What the record does not prove

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

In particular, the record shows what was authorised. It does not show that you executed it; that is your log's job.
