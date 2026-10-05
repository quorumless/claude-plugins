# claude-plugins

Claude Code mods, published as a plugin marketplace.

## Install

Add the marketplace once per machine:

```
claude plugin marketplace add quorumless/claude-plugins
```

Then install only the mods you want on that machine:

```
claude plugin install <plugin>@quorumless-plugins
```

Syncing the marketplace enables nothing. A mod runs only where you install it. Disable one without uninstalling with `claude plugin disable <plugin>`.

## Plugins

| Plugin | What it does |
|--------|--------------|
| `agent-status` | Background agents above the prompt and in an `/agents` pane: runtime, last response, last call |
| `cc-status` | Status line: model, context usage circle (green <50%, yellow <75%, red above) with window size, secret-guard lock. Expects `secret-guard` to be installed |
| `secret-guard` | Masks secrets in prompts, subagent messages and tool output; restores them only when a tool runs; blocks commits that leak them; `/secret` copies one to the clipboard |

## Development

`secret-guard` has a self-test: `node plugins/secret-guard/hooks/redact.ts` prints `redact: ok`.
