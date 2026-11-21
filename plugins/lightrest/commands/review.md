---
description: Send a file, or the last assistant message, to a person in your LightRest organization for review
argument-hint: "[file]"
---

Request a human review of $ARGUMENTS through the `lightrest` MCP server.

1. If a file path was given, read it and use its full contents as `aiOutputText`. If no argument was given, use your last assistant message. Under local custody (`@lightrest/mcp` with `LIGHTREST_CONTENT_CUSTODY=local`) send it the same way; the proxy keeps the text on this machine and sends only its digest.
2. Call `request_human_review` with `subjectType: "draft"`, `aiSystem: { name: "Claude Code" }`, and `externalRef` set to the file path (or `last-message-<ISO timestamp>` when there is none).
3. Follow the `human-review` skill from "While waiting" onward: give the user the `reviewUrl`, wait, then continue with `humanFinalText` and quote the record id and `verifyUrl`.
