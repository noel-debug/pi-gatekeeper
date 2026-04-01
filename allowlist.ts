/**
 * Safe Command Allowlist (Default-Deny)
 *
 * Only commands listed here are allowed to run without user approval.
 * Everything else is gated — the user must explicitly approve it.
 *
 * Each entry is either:
 *   `true`                        → always safe regardless of arguments
 *   `(args: string[]) => boolean` → safe only when the predicate returns true
 *
 * Design principle: false positives (unnecessary prompts) are annoying but safe.
 * False negatives (missed mutations) are dangerous. When in doubt, omit the command.
 */

export type CommandRule = true | ((args: string[]) => boolean);

// ── Git helpers ─────────────────────────────────────────────────────────

/** Git subcommands that are always read-only */
const ALWAYS_SAFE_GIT = new Set([
	"status", "log", "diff", "show", "blame", "shortlog", "describe",
	"ls-files", "ls-tree", "ls-remote",
	"rev-parse", "rev-list", "cat-file",
	"count-objects", "verify-commit", "verify-tag",
	"for-each-ref", "reflog", "name-rev", "merge-base",
	"diff-tree", "diff-index", "diff-files",
	"whatchanged", "show-ref",
	"check-ignore", "check-attr",
	"version", "help",
]);

/** Git subcommands safe only in list mode (no positional args that mutate) */
const GIT_LIST_ONLY = new Set(["branch", "tag", "remote", "stash", "config"]);

/** Git global flags that consume the next argument as a value */
const GIT_VALUE_FLAGS = new Set(["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--exec-path"]);

function extractGitSubcommand(args: string[]): { sub: string; subArgs: string[] } | null {
	let i = 0;
	while (i < args.length) {
		const a = args[i];
		if (!a.startsWith("-")) return { sub: a, subArgs: args.slice(i + 1) };
		const flag = a.split("=")[0];
		if (GIT_VALUE_FLAGS.has(flag) && !a.includes("=")) i++; // skip value
		i++;
	}
	return null;
}

function isGitListOnlySafe(sub: string, subArgs: string[]): boolean {
	if (sub === "stash") {
		// bare `git stash` = `git stash push` (mutation)
		if (subArgs.length === 0) return false;
		return subArgs[0] === "list" || subArgs[0] === "show";
	}
	if (sub === "config") {
		const flags = subArgs.filter(a => a.startsWith("-"));
		if (flags.some(f => ["--list", "-l", "--get", "--get-all", "--get-regexp"].includes(f))) return true;
		const nonFlags = subArgs.filter(a => !a.startsWith("-"));
		if (nonFlags.length <= 1 && !flags.some(f => ["--set", "--add", "--unset", "--unset-all", "--replace-all", "--rename-section", "--remove-section"].includes(f))) return true;
		return false;
	}
	// branch, tag, remote: safe if only flags (no positional args that create/delete)
	return subArgs.filter(a => !a.startsWith("-")).length === 0;
}

function isGitSafe(args: string[]): boolean {
	if (args.length === 0) return true;
	if (args.includes("--version") || args.includes("--help") || args.includes("-h")) return true;
	const extracted = extractGitSubcommand(args);
	if (!extracted) return true; // only flags, no subcommand
	if (ALWAYS_SAFE_GIT.has(extracted.sub)) return true;
	if (GIT_LIST_ONLY.has(extracted.sub)) return isGitListOnlySafe(extracted.sub, extracted.subArgs);
	return false;
}

// ── Package manager helpers ─────────────────────────────────────────────

const SAFE_NPM_SUBS = new Set([
	"ls", "list", "view", "info", "show", "search", "outdated",
	"audit", "why", "explain", "help", "version", "--version", "-v",
	"bin", "prefix", "root", "query", "fund",
	// NOTE: "pack" intentionally excluded — it creates a tarball in cwd
]);

function isNpmSafe(args: string[]): boolean {
	return args.length > 0 && SAFE_NPM_SUBS.has(args[0]);
}

// ── Conditional-safe helpers ────────────────────────────────────────────

function isFindSafe(args: string[]): boolean {
	const dangerous = ["-delete", "-exec", "-execdir", "-ok", "-okdir"];
	return !args.some(a => dangerous.includes(a));
}

function isSedSafe(args: string[]): boolean {
	// -i / --in-place modifies files
	if (args.some(a => a === "-i" || a.startsWith("-i") || a === "--in-place")) return false;
	// sed's 'w' and 'W' commands write to files from within expressions
	// e.g. sed -n 'w /tmp/file' or sed '1w output.txt'
	const exprArgs = getSedExpressions(args);
	if (exprArgs.some(e => /\bw\s/i.test(e))) return false;
	return true;
}

/** Extract sed expression arguments (from -e args and bare args) */
function getSedExpressions(args: string[]): string[] {
	const exprs: string[] = [];
	for (let i = 0; i < args.length; i++) {
		if (args[i] === "-e" && i + 1 < args.length) {
			exprs.push(args[++i]);
		} else if (!args[i].startsWith("-")) {
			// First non-flag non-file arg is the expression (heuristic)
			exprs.push(args[i]);
		}
	}
	return exprs;
}

function isCurlSafe(args: string[]): boolean {
	for (const a of args) {
		if (["-o", "--output", "-O", "--remote-name", "-J", "--remote-header-name"].includes(a)) return false;
		if (a.startsWith("-") && !a.startsWith("--") && (a.includes("o") || a.includes("O") || a.includes("J"))) return false;
	}
	return true;
}

function isAwkSafe(args: string[]): boolean {
	// awk can write files via its own '>' redirect in program text
	// e.g. awk '{print > "file"}' or awk 'BEGIN{print > "/tmp/f"}'
	for (const a of args) {
		if (!a.startsWith("-") && (a.includes(">") || a.includes(">>") || /\bsystem\s*\(/.test(a))) {
			return false;
		}
	}
	return true;
}

function isSortSafe(args: string[]): boolean {
	return !args.some(a => a === "-o" || a === "--output");
}

function isTarSafe(args: string[]): boolean {
	if (args.length === 0) return false;
	const a = args[0];
	if (a === "--list" || a === "-t") return true;
	// Old-style or combined: must have 't' (list) and NOT 'x'/'c'/'r'/'u' (extract/create/append/update)
	const relevant = a.startsWith("-") ? a.slice(1) : a;
	return relevant.includes("t") && !/[xcru]/.test(relevant);
}

function versionOnly(args: string[]): boolean {
	return args.some(a => ["--version", "-v", "-V", "-version"].includes(a));
}

// ── Allowlist ───────────────────────────────────────────────────────────

export const SAFE_COMMANDS: Record<string, CommandRule> = {
	// ── File viewing ────────────────────────────────────────────────
	"cat": true, "head": true, "tail": true, "less": true, "more": true,
	"bat": true, "batcat": true,

	// ── Directory listing ───────────────────────────────────────────
	"ls": true, "ll": true, "la": true, "dir": true, "tree": true,
	"exa": true, "eza": true, "lsd": true,

	// ── Search ──────────────────────────────────────────────────────
	"grep": true, "egrep": true, "fgrep": true,
	"rg": true, "ag": true, "ack": true, "pt": true,

	// ── Find (conditional) ──────────────────────────────────────────
	"find": isFindSafe,
	"fd": true, "fzf": true, "locate": true, "mdfind": true,

	// ── File info ───────────────────────────────────────────────────
	"file": true, "stat": true, "wc": true, "du": true, "df": true,
	"readlink": true, "realpath": true, "basename": true, "dirname": true,
	"sha256sum": true, "sha1sum": true, "sha512sum": true, "shasum": true,
	"md5sum": true, "md5": true, "cksum": true, "b2sum": true, "sum": true,

	// ── Text processing (stdout-only) ───────────────────────────────
	"awk": isAwkSafe, "gawk": isAwkSafe, "mawk": isAwkSafe,
	"sed": isSedSafe,
	"sort": isSortSafe,
	"uniq": true, "cut": true, "tr": true, "paste": true, "column": true,
	"fmt": true, "fold": true, "expand": true, "unexpand": true,
	"nl": true, "pr": true, "rev": true, "tac": true,
	"strings": true, "od": true, "xxd": true, "hexdump": true,

	// ── Comparison ──────────────────────────────────────────────────
	"diff": true, "colordiff": true, "cmp": true, "comm": true,

	// ── System info ─────────────────────────────────────────────────
	"whoami": true, "hostname": true, "uname": true, "id": true,
	"groups": true, "env": true, "printenv": true, "locale": true,
	"uptime": true, "arch": true, "nproc": true, "getconf": true,

	// ── Path / shell utilities ──────────────────────────────────────
	"which": true, "where": true, "type": true, "hash": true, "pwd": true,
	"echo": true, "printf": true, "yes": true, "true": true, "false": true,
	"seq": true, "expr": true, "bc": true, "dc": true,
	"sleep": true, "wait": true,
	// NOTE: "time" intentionally excluded — it's a BENIGN_WRAPPER that
	// executes its argument as a command (time rm file → runs rm)

	// ── Date / time ─────────────────────────────────────────────────
	"date": true, "cal": true, "ncal": true,

	// ── JSON / data ─────────────────────────────────────────────────
	"jq": true, "yq": true, "xmllint": true, "xsltproc": true,

	// ── Network (read-only) ─────────────────────────────────────────
	"ping": true, "dig": true, "nslookup": true, "host": true,
	"traceroute": true, "tracepath": true, "mtr": true,
	"curl": isCurlSafe,
	"wget": (args) => args.includes("--spider"),
	"whois": true, "ss": true, "netstat": true, "ifconfig": true,

	// ── Process info ────────────────────────────────────────────────
	"ps": true, "top": true, "htop": true, "btop": true,
	"pgrep": true, "lsof": true, "time": true,

	// ── Test / conditionals ─────────────────────────────────────────
	"test": true, "[": true,

	// ── Git (conditional) ───────────────────────────────────────────
	"git": isGitSafe,

	// ── Package managers (read-only subcommands) ────────────────────
	"npm": isNpmSafe, "yarn": isNpmSafe, "pnpm": isNpmSafe, "bun": isNpmSafe,
	"deno": (args) => args.length > 0 && ["info", "doc", "lint", "check", "types", "help", "--version", "-V"].includes(args[0]),
	"cargo": (args) => args.length > 0 && ["check", "clippy", "doc", "tree", "metadata", "search", "version", "help", "--version", "-V"].includes(args[0]),
	"pip": (args) => args.length > 0 && ["list", "show", "freeze", "check", "help", "--version", "-V"].includes(args[0]),
	"pip3": (args) => args.length > 0 && ["list", "show", "freeze", "check", "help", "--version", "-V"].includes(args[0]),

	// ── Archive (conditional) ───────────────────────────────────────
	"tar": isTarSafe,
	"zipinfo": true,
	"unzip": (args) => args.includes("-l") || args.includes("-Z"),

	// ── Interpreters (version-only) ─────────────────────────────────
	"node": versionOnly, "python3": versionOnly, "python": versionOnly,
	"ruby": versionOnly, "perl": versionOnly, "php": versionOnly,
	"rustc": versionOnly, "java": versionOnly, "javac": versionOnly,
	"gcc": versionOnly, "g++": versionOnly, "clang": versionOnly,
	"swift": versionOnly,
	"go": (args) => args.length > 0 && ["version", "env", "help", "doc"].includes(args[0]),
	"make": (args) => args.some(a => ["--version", "-v", "-n", "--dry-run", "--just-print"].includes(a)),
	"cmake": (args) => args.includes("--version") || args.includes("--help"),
	"dotnet": (args) => args.length > 0 && ["--version", "--list-sdks", "--list-runtimes", "--info", "help"].includes(args[0]),

	// ── Shell navigation (harmless) ─────────────────────────────────
	"cd": true, "pushd": true, "popd": true, "dirs": true,
	"set": true, "shopt": true,

	// ── Misc safe ───────────────────────────────────────────────────
	"man": true, "info": true, "help": true, "clear": true, "reset": true,
	"tput": true, "stty": true, "tty": true,
	"open": true, "xdg-open": true,
	"pbcopy": true, "pbpaste": true, "xclip": true, "xsel": true,
};

// ── Benign command wrappers ─────────────────────────────────────────────
// These prefix another command without adding danger.
// The analyzer unwraps them to check the inner command.

export const BENIGN_WRAPPERS = new Set([
	"env", "nice", "nohup", "builtin", "command", "time",
	"stdbuf", "timeout", "ionice", "chrt", "taskset", "setsid",
]);
