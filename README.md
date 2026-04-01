# 🛡️ Gatekeeper

A [pi](https://github.com/badlogic/pi-mono) extension that adds a permission system. File-mutating tool calls require user approval before execution.

## How It Works

Gatekeeper uses a **default-deny** model with **AST-based analysis**:

1. **`edit` and `write`** tool calls are always gated
2. **`bash`** commands are parsed into an AST using [tree-sitter-bash](https://github.com/tree-sitter/tree-sitter-bash), then classified:
   - Every command in the AST is checked against a [safe command allowlist](allowlist.ts)
   - Output redirections (`>`, `>>`) are detected structurally
   - Dynamic/unresolvable constructs (command substitution, variable expansion, ANSI-C strings in command position) are always gated
   - Benign command wrappers (`env`, `nice`, `nohup`, `timeout`, etc.) are unwrapped to check the inner command
   - Compound commands (`&&`, `||`, `;`, pipes, loops, conditionals) have every sub-command checked
   - Parse errors trigger gating (possible obfuscation)
   - Falls back to regex patterns if tree-sitter is unavailable

**Design principle:** if the analyzer can't prove a command is safe, it's gated. False positives (unnecessary prompts) are annoying but harmless. False negatives (missed mutations) are dangerous.

## Allowed without asking

Commands on the allowlist pass through silently. This includes:

| Category | Commands |
|----------|----------|
| **File viewing** | `cat`, `head`, `tail`, `less`, `bat` |
| **Listing** | `ls`, `tree`, `exa`, `eza` |
| **Search** | `grep`, `rg`, `ag`, `find` (without `-delete`/`-exec`), `fd` |
| **File info** | `file`, `stat`, `wc`, `du`, `df`, `readlink` |
| **Text processing** | `awk`, `sed` (without `-i`), `sort` (without `-o`), `uniq`, `cut`, `tr`, `jq` |
| **Comparison** | `diff`, `cmp`, `comm` |
| **System info** | `whoami`, `uname`, `env`, `printenv`, `uptime` |
| **Shell utils** | `echo`, `printf`, `pwd`, `which`, `type`, `test`, `cd` |
| **Network (read)** | `ping`, `dig`, `curl` (without `-o`/`-O`), `wget --spider` |
| **Git (read)** | `status`, `log`, `diff`, `show`, `blame`, `branch` (list), `tag` (list) |
| **Pkg mgrs (read)** | `npm ls`, `npm outdated`, `npm audit`, `cargo check`, `pip list` |
| **Interpreters** | Only `--version` / `-v` checks |
| **Redirects** | `> /dev/null`, `2>&1`, `< input` (input redirects) |

See [`allowlist.ts`](allowlist.ts) for the complete list.

## Gated (requires approval)

Everything not on the allowlist, including:

- File mutation: `rm`, `mv`, `cp`, `mkdir`, `touch`, `chmod`, `ln`, `rsync`, `tee`, `dd`, ...
- Output redirects: `> file.txt`, `>> file.txt`
- Git mutations: `push`, `commit`, `add`, `checkout`, `reset`, `rebase`, `merge`, ...
- Package mutations: `npm install`, `npm run`, `yarn add`, ...
- Shell execution: `bash -c`, `sh -c`, `eval`, `source`, `exec`
- Interpreters with code: `python3 -c`, `node -e`, `ruby -e`, ...
- Privilege escalation: `sudo`, `doas`
- Obfuscation: `$(cmd)` in command position, `$var` in command position, ANSI-C strings, parse errors

## Obfuscation resistance

The AST-based approach defeats common evasion techniques:

| Technique | How it's caught |
|-----------|----------------|
| `$(echo rm) file` | Dynamic command name (command substitution) |
| `$cmd file` | Dynamic command name (variable expansion) |
| `$'\x72\x6d' file` | Dynamic command name (ANSI-C string) |
| `/bin/rm file` | Path stripped → `rm` → not in allowlist |
| `\rm file` | Backslash stripped → `rm` → not in allowlist |
| `"rm" file` / `'rm' file` | Quoted name resolved → `rm` → not in allowlist |
| `env rm file` | Wrapper unwrapped → `rm` → not in allowlist |
| `nice env nohup rm file` | Stacked wrappers unwrapped → `rm` |
| `echo x \| base64 -d \| sh` | `sh` not in allowlist |
| `echo x > file.txt` | Output redirect detected structurally |
| `echo safe; rm bad` | Every sub-command checked |
| `for f in *; do rm $f; done` | Loop body checked |
| Malformed input | Parse errors → gated |

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

```bash
pi install npm:@eigenwert/pi-gatekeeper
# or
pi install git:github.com/noel-debug/pi-gatekeeper
```

Or manually:

```bash
mkdir -p ~/.pi/agent/extensions/gatekeeper
cp index.ts dialog.ts patterns.ts analyzer.ts allowlist.ts package.json ~/.pi/agent/extensions/gatekeeper/
cd ~/.pi/agent/extensions/gatekeeper && npm install
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                 Incoming bash command                │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│  tree-sitter-bash AST parse                         │
│  Parse errors → GATE                                │
│  Falls back to regex if WASM unavailable            │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│  AST walk — classify every node                     │
│  • command → resolve name, unwrap wrappers          │
│  • file_redirect → check for >, >>                  │
│  • dynamic constructs → GATE                        │
│  • function_definition → GATE                       │
│  • recurse into compound/control-flow nodes         │
└──────────────────────┬──────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│  Default-deny allowlist check                       │
│  Command in allowlist with safe args → ALLOW        │
│  Unknown command → GATE                             │
└──────────────────────┬──────────────────────────────┘
                       ▼
                 ALLOW or GATE
```

## License

MIT
