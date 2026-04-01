# 🛡️ Gatekeeper

A [pi](https://github.com/badlogic/pi-mono) extension that adds a permission system. File-mutating tool calls require user approval before execution.

## Gated operations

- **edit** — file edits (shows full diff in the dialog)
- **write** — file creation/overwrite (shows file content in the dialog)
- **bash** — only file/folder-mutating commands:
  - Deletion: `rm`, `rmdir`, `unlink`, `trash`, `srm`, `shred`
  - Move/copy: `mv`, `cp`, `rsync`
  - Create: `mkdir`, `touch`, `ln`
  - Modify: `chmod`, `chown`, `truncate`
  - Write: `tee`, `dd`

All other tool calls (`read`, `grep`, `find`, `ls`, harmless bash like `cat`, `git`, etc.) go through without asking.

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

Copy `index.ts` to `~/.pi/agent/extensions/gatekeeper/`:

```bash
mkdir -p ~/.pi/agent/extensions/gatekeeper
cp index.ts ~/.pi/agent/extensions/gatekeeper/
```

Or install as a pi package:

```bash
pi install git:github.com/noel-debug/pi-gatekeeper
```

## License

MIT
