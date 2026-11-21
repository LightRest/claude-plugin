---
name: human-review
description: Use when an output you produced will be filed, sent, published, or acted on in a regulated or high-stakes setting (a court filing, a coverage decision, a model risk memo, a customer-facing determination), or whenever the user asks for a person to review it. Requests a review through the LightRest MCP server, waits for the reviewer, and continues with the text they stood behind and the sealed record's id. Not for drafts, brainstorming, or anything the user will rewrite anyway.
---

# Request a human review

The `lightrest` MCP server hands your output to a person in the user's LightRest organization. They read it, edit it if they choose, decide, and seal the result in a browser with their own passkey. You get back the text they stood behind and a Human Review Record you can cite. Nothing you call here seals anything.

## When to request

- The output will be filed, sent, published, or acted on in a regulated or high-stakes context.
- The user asks for a human to review, sign off, or approve.
- A sector profile applies (health utilization management, legal filings, bank model risk, EU AI Act Article 14 oversight).

Never for trivial outputs, intermediate drafts, or content the user is about to rewrite. Never send credentials, keys, or personal data the review does not need: send the text that will be relied on and nothing else.

## How

1. Call `request_human_review` with:
   - `aiOutputText`: the exact text to be reviewed.
   - `subjectType`: what it is (for example `draft`; under the US legal filing profile, `court_filing`, `legal_research_memo` or `citation_check`). If the reviewer will seal under a sector profile, use one of that profile's subjects: the seal refuses any other.
   - `aiSystem`: `{ name, version }` for yourself, honestly.
   - `externalRef`: a stable id of the artifact (file path, ticket, document id) so a repeat call for the same artifact is recognised.
   It returns `captureId`, `reviewUrl`, and `expiresAt`.
   Send `aiOutputText` the same way when the organisation keeps content local: if the server runs through `@lightrest/mcp` with `LIGHTREST_CONTENT_CUSTODY=local`, the proxy stores the text on this machine and sends only its digest. Do not hash it yourself.
2. If the client supports MCP Tasks, use the task form and wait on it. Otherwise poll `get_review` with the `captureId` no more often than every 15 seconds, backing off to 60 seconds, and stop at `expiresAt`.

## While waiting

Tell the user the `reviewUrl` and that a member of their organization must open it and complete the review. Do not proceed with the draft, and do not produce a substitute.

## After

- `status: "sealed"` or `"credentialed"`: continue with the text `get_review` returns (`humanFinalText`), exactly as returned, and with nothing else. It never returns your original output, and you do not fall back to your draft. Do not restore anything the reviewer removed and do not polish their wording.
- Local custody: if the record is sealed but has no `humanFinalText` and the text says the authorised text has not reached this machine's store, do not continue. Keep polling `get_review` until the proxy fills the text in.
- `decision: "rejected"`: stop, report the reviewer's rationale to the user, and do not use the output.
- Quote the record id (`OR-…`) and the `verifyUrl` wherever the output is delivered. While `credential` is `"not_issued"` (for example, awaiting a witness) there is no `verifyUrl` yet: quote the record id and say the credential has not been issued.

## What you may say

Say: "A human review record exists: <record id>, <verifyUrl>." That sentence is true as soon as `get_review` returns a sealed record.

Say "verified" about a record only after `verify_record` has returned `verified: true` for it. Until then you have not verified anything, and neither has anyone else on your behalf.

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

If the user asks what a record establishes, answer from this list and from the tool's own description, not from memory.
