# 🛡️ Gatekeeper

A [pi](https://github.com/badlogic/pi-mono) extension that adds a permission system. File-mutating tool calls require user approval before execution.

## Gated operations

- **edit** — file edits
- **write** — file creation/overwrite
- **bash** — only `rm`, `rmdir`, `unlink`, `trash`, `srm`, `mv`, `cp`, `rsync`

All other tool calls (read, grep, find, ls, harmless bash) go through without asking.

## Dialog

When a gated tool call is intercepted, a dialog appears showing what the tool wants to do (including full diffs for edits).

| Key | Action |
|-----|--------|
| `y` | Accept this tool call |
| `n` | Decline this tool call |
| `a` | Switch to auto-accept mode |
| `←` `→` | Navigate options |
| `Tab` | Attach a message to Yes/No (the LLM sees your feedback) |
| `Enter` | Confirm highlighted option |
| `Esc` | Decline |

## Commands

- `/gatekeeper` — Toggle between `ask` (default) and `auto-accept` mode

## Install

Copy `gatekeeper.ts` to `~/.pi/agent/extensions/`:

```bash
cp gatekeeper.ts ~/.pi/agent/extensions/
```

Or install as a pi package:

```bash
pi install git:github.com/noel-debug/pi-gatekeeper
```

## License

MIT
