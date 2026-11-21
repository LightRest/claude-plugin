---
description: Check a LightRest Human Review Record by HOC-… id, verify link, or credential JSON file
argument-hint: "<HOC-id | verify link | file>"
---

Check the LightRest record $ARGUMENTS through the `lightrest-verify` MCP server.

1. If no argument was given, ask for an `HOC-…` id, a `https://lightrest.net/verify/HOC-…` link, or a credential JSON file, and stop.
2. Follow the `verify-record` skill: pass an id or link as `credentialId`, or the file's JSON object unchanged as `credential`, to `verify_record`.
3. Report the result as the skill's "Report the result" section says.
