# LightRest plugin marketplace

This directory is the root of the public repository `LightRest/claude-plugin`: a Claude Code plugin marketplace with two plugins: `lightrest` (request reviews, action guard) at `plugins/lightrest`, and `lightrest-verify` (check a record, no account) at `plugins/lightrest-verify`.

```
/plugin marketplace add LightRest/claude-plugin
/plugin install lightrest@lightrest
/plugin install lightrest-verify@lightrest
```

Neither plugin directory is kept here; `scripts/sync-claude-plugin.sh` copies `integrations/claude-plugin` and `integrations/claude-plugin-verify` into them in a checkout of the public repository. See `integrations/claude-plugin/README.md`.
