/**
 * Bash Command Analyzer
 *
 * Uses tree-sitter-bash to parse shell commands into an AST, then walks
 * the tree to classify whether the command could mutate files.
 *
 * Detection layers:
 *   1. AST parse via tree-sitter-bash (structural analysis)
 *   2. Default-deny allowlist for every resolved command
 *   3. Output redirection detection (>, >>)
 *   4. Dynamic/unresolvable construct detection (command substitution,
 *      variable expansion, ANSI-C strings in command position → gate)
 *
 * Failure mode: if any layer can't determine safety, the command is gated.
 * Parse errors, unknown constructs, and dynamic names all trigger gating.
 */

import { dirname, join } from "node:path";
import { BENIGN_WRAPPERS, SAFE_COMMANDS } from "./allowlist";

// ── Types ───────────────────────────────────────────────────────────────

// We use `any` for tree-sitter types to avoid import issues with WASM module.
// The actual runtime objects are fully typed by web-tree-sitter.
type SyntaxNode = any;
type ParserInstance = any;

export interface AnalysisResult {
	/** Whether this command should be gated (require user approval) */
	gated: boolean;
	/** Human-readable reasons why the command is gated */
	reasons: string[];
}

// ── Parser singleton ────────────────────────────────────────────────────

let parserPromise: Promise<ParserInstance | null> | null = null;

async function getParser(): Promise<ParserInstance | null> {
	if (!parserPromise) parserPromise = initParser();
	return parserPromise;
}

async function initParser(): Promise<ParserInstance | null> {
	try {
		const { Parser, Language } = await import("web-tree-sitter");

		// Locate WASM files via package resolution
		// Use the main entry point to find the package directory
		// (web-tree-sitter's exports map blocks /package.json)
		const tsPkgDir = dirname(require.resolve("web-tree-sitter"));
		const bashPkgDir = dirname(require.resolve("tree-sitter-bash/package.json"));

		// WASM filename changed in 0.26.x: tree-sitter.wasm → web-tree-sitter.wasm
		const wasmCandidates = ["web-tree-sitter.wasm", "tree-sitter.wasm"];
		const { existsSync } = await import("node:fs");
		const wasmFile = wasmCandidates.find(f => existsSync(join(tsPkgDir, f))) ?? wasmCandidates[0];

		await Parser.init({
			locateFile: () => join(tsPkgDir, wasmFile),
		});

		const parser = new Parser();
		const Bash = await Language.load(join(bashPkgDir, "tree-sitter-bash.wasm"));
		parser.setLanguage(Bash);
		return parser;
	} catch (err) {
		console.error("Gatekeeper: tree-sitter init failed, using regex fallback.", err);
		return null;
	}
}

// ── Public API ──────────────────────────────────────────────────────────

export async function analyzeCommand(command: string): Promise<AnalysisResult> {
	const parser = await getParser();
	if (!parser) return { gated: isGatedFallback(command), reasons: ["tree-sitter unavailable — regex fallback matched a potentially mutating pattern"] };

	const tree = parser.parse(command);
	try {
		const root = tree.rootNode;

		// Parse errors → gate (possible obfuscation or complex construct)
		if (root.hasError) {
			return { gated: true, reasons: ["shell parser reported syntax errors — possible obfuscation or complex construct"] };
		}

		const reasons: string[] = [];
		classifyNode(root, reasons);
		return { gated: reasons.length > 0, reasons };
	} finally {
		// Tree-sitter WASM trees must be explicitly freed to avoid
		// accumulating allocations over long-running sessions.
		tree.delete();
	}
}

// ── AST walker ──────────────────────────────────────────────────────────

/**
 * Node classification strategy:
 *
 * - "command"             → extract name, unwrap wrappers, check allowlist,
 *                           then scan children for nested executable code
 * - "file_redirect"       → check for output operators (>, >>)
 * - "function_definition" → always gate (defines callable code)
 * - Leaf-inert nodes      → skip (only truly non-executable: comments, heredoc text)
 * - Everything else       → recurse into named children
 *
 * Unknown named node types hit the default branch which recurses.
 * This ensures we never silently skip a dangerous construct.
 */

/**
 * Node types that can NEVER contain executable code.
 * Everything else is recursed into — this is critical for catching
 * command substitutions in variable assignments, test expressions, etc.
 * e.g. FOO=$(rm file), [ $(rm file) ], export BAR=$(touch x)
 */
const LEAF_INERT = new Set([
	"comment", "heredoc_body", "heredoc_start", "heredoc_end",
]);

function classifyNode(node: SyntaxNode, reasons: string[]): void {
	// ERROR nodes from tree-sitter error recovery
	if (node.type === "ERROR" || node.isError) {
		reasons.push(`AST parse error near \`${node.text.slice(0, 40)}\` — possible obfuscation or unsupported syntax`);
		return;
	}

	switch (node.type) {
		case "command":
			classifyCommand(node, reasons);
			return;

		case "pipeline":
			classifyPipeline(node, reasons);
			return;

		case "file_redirect":
			classifyFileRedirect(node, reasons);
			return;

		case "function_definition":
			reasons.push("function definition — defines callable code that cannot be statically analyzed");
			return;

		default:
			// Leaf-inert nodes: can never contain executable code
			if (LEAF_INERT.has(node.type)) return;

			// Everything else: recurse into named children
			// This covers: program, list, pipeline, redirected_statement,
			// subshell, compound_statement, for_statement, while_statement,
			// if_statement, case_statement, negated_command, do_group,
			// elif_clause, else_clause, case_item, heredoc_redirect, etc.
			for (let i = 0; i < node.childCount; i++) {
				const child = node.child(i);
				if (child && child.isNamed) classifyNode(child, reasons);
			}
			return;
	}
}

// ── Pipeline classification ──────────────────────────────────────────────

/** Shell commands that execute their stdin as code */
const SHELL_EXECUTORS = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish"]);

/**
 * Detect encoded payload pipelines like `echo <base64> | base64 -d | sh`.
 * When found, decode the payload and report what actually executes.
 */
function classifyPipeline(node: SyntaxNode, reasons: string[]): void {
	// Collect pipeline stages
	const stages: SyntaxNode[] = [];
	for (let i = 0; i < node.childCount; i++) {
		const child = node.child(i);
		if (child && child.isNamed) stages.push(child);
	}

	// Look for pattern: ... | base64 -d | <shell>
	const decoded = tryDecodePipelinePayload(stages);
	if (decoded) {
		reasons.push(
			`encoded pipeline \`${node.text.slice(0, 80)}\` \u2014 ` +
			`base64 payload decodes to: \`${decoded.payload.trim()}\` \u2192 piped to \`${decoded.shell}\` for execution`
		);
		return;
	}

	// No special pattern detected \u2014 classify each stage individually
	for (const stage of stages) {
		classifyNode(stage, reasons);
	}
}

interface DecodedPipeline {
	payload: string;
	shell: string;
}

/** Try to extract and decode a base64 payload from a pipeline */
function tryDecodePipelinePayload(stages: SyntaxNode[]): DecodedPipeline | null {
	if (stages.length < 2) return null;

	// Check if the last stage is a shell executor
	const lastStage = stages[stages.length - 1];
	const lastCmd = getCommandName(lastStage);
	if (!lastCmd || !SHELL_EXECUTORS.has(lastCmd)) return null;

	// Look for a base64 decode stage before it
	let base64Idx = -1;
	for (let i = stages.length - 2; i >= 0; i--) {
		const cmd = getCommandName(stages[i]);
		if (cmd === "base64" && hasFlag(stages[i], "-d", "--decode", "-D")) {
			base64Idx = i;
			break;
		}
	}
	if (base64Idx < 0) return null;

	// Try to extract the literal payload from stages before base64
	const payload = extractLiteralPayload(stages, base64Idx);
	if (!payload) return null;

	// Decode
	try {
		const decoded = Buffer.from(payload, "base64").toString("utf-8");
		// Sanity check: must produce printable text
		if (!/^[\x09\x0a\x0d\x20-\x7e]+$/.test(decoded)) return null;
		return { payload: decoded, shell: lastCmd };
	} catch {
		return null;
	}
}

/** Get the resolved command name from a command node */
function getCommandName(node: SyntaxNode): string | null {
	if (node.type !== "command") return null;
	const nameNode = node.childForFieldName("name");
	if (!nameNode) return null;
	return resolveCommandName(nameNode);
}

/** Check if a command node has a specific flag */
function hasFlag(node: SyntaxNode, ...flags: string[]): boolean {
	const args = getCommandArgs(node);
	return args.some(a => flags.includes(a));
}

/** Extract the literal string payload fed into a base64 -d stage */
function extractLiteralPayload(stages: SyntaxNode[], base64Idx: number): string | null {
	if (base64Idx === 0) return null;
	const feedStage = stages[base64Idx - 1];
	if (feedStage.type !== "command") return null;
	const cmd = getCommandName(feedStage);
	if (cmd !== "echo" && cmd !== "printf") return null;
	const args = getCommandArgs(feedStage);
	if (args.length === 0) return null;
	// Return the last argument (the payload), stripping quotes
	let payload = args[args.length - 1];
	if ((payload.startsWith("'") && payload.endsWith("'")) ||
		(payload.startsWith('"') && payload.endsWith('"'))) {
		payload = payload.slice(1, -1);
	}
	return payload;
}

// ── Command classification ──────────────────────────────────────────────

function classifyCommand(node: SyntaxNode, reasons: string[]): void {
	const nameNode = node.childForFieldName("name");
	if (!nameNode) {
		reasons.push("command node has no name field — cannot determine what will execute");
		return;
	}

	// Resolve the static command name
	const resolved = resolveCommandName(nameNode);
	if (!resolved) {
		reasons.push(describeDynamicName(nameNode));
		return;
	}

	const args = getCommandArgs(node);

	// Special case: `command -v/-V` is a type-check, always safe
	if (resolved === "command" && args.length > 0 && (args[0] === "-v" || args[0] === "-V")) {
		scanCommandChildren(node, reasons);
		return;
	}

	// Unwrap benign wrappers (env, nice, nohup, etc.)
	const unwrapped = unwrapCommand(resolved, args);

	// Check the unwrapped command against the allowlist
	const rule = SAFE_COMMANDS[unwrapped.command];
	if (rule === undefined) {
		const detail = unwrapped.command !== resolved
			? ` (resolved from \`${resolved} ${args.join(" ")}\`)` : "";
		reasons.push(`\`${unwrapped.command}\` is not in the safe command allowlist${detail} — default-deny policy gates unknown commands`);
		return; // Already gated — no need to scan further
	}
	if (rule !== true && !rule(unwrapped.commandArgs)) {
		const argStr = unwrapped.commandArgs.length > 0 ? ` with args [${unwrapped.commandArgs.join(", ")}]` : "";
		reasons.push(`\`${unwrapped.command}\`${argStr} — allowlisted command but arguments indicate file mutation`);
		return; // Already gated
	}

	// Command itself passes the allowlist, but children may still contain
	// dangerous nested code: output redirects (>, >>), command substitutions
	// in arguments — echo $(rm file), or env-var assignments with embedded
	// commands — FOO=$(rm file) echo hi.
	scanCommandChildren(node, reasons);
}

/**
 * Scan all non-name children of a command node for nested executable code.
 * Handles: output redirects, command substitutions in arguments/strings,
 * variable assignments with embedded commands, etc.
 */
function scanCommandChildren(node: SyntaxNode, reasons: string[]): void {
	for (let i = 0; i < node.childCount; i++) {
		const child = node.child(i);
		if (!child || !child.isNamed) continue;
		if (child.type === "command_name") continue; // already resolved above
		classifyNode(child, reasons);
	}
}

// ── Dynamic name diagnostics ────────────────────────────────────────────

const DYNAMIC_NAME_DESCRIPTIONS: Record<string, string> = {
	command_substitution: "command substitution `$(...)` in command position — executed command is determined at runtime",
	simple_expansion: "variable expansion `$var` in command position — command name resolved at runtime from variable",
	expansion: "parameter expansion `${...}` in command position — command name resolved at runtime",
	process_substitution: "process substitution `<(...)` in command position — cannot statically determine command",
	concatenation: "string concatenation in command position — fragments may assemble an arbitrary command name",
};

function describeDynamicName(nameNode: SyntaxNode): string {
	const child = nameNode.childCount > 0 ? nameNode.child(0) : null;
	const nodeType = child?.type ?? "unknown";
	const snippet = nameNode.text.slice(0, 60);

	// ANSI-C strings: decode and show the actual command
	if (nodeType === "ansi_c_string" && child) {
		const decoded = decodeAnsiCString(child.text);
		return `\`${snippet}\` decodes to \`${decoded}\` — ANSI-C quoting \`$'...'\` in command position encodes command name via escape sequences`;
	}

	const description = DYNAMIC_NAME_DESCRIPTIONS[nodeType]
		?? `dynamic construct (AST node: ${nodeType}) — cannot statically resolve command name`;
	return `\`${snippet}\` — ${description}`;
}

/** Decode a bash ANSI-C quoted string: $'\x72\x6d' → rm */
function decodeAnsiCString(raw: string): string {
	// Strip the $' prefix and ' suffix
	let s = raw;
	if (s.startsWith("$'") && s.endsWith("'")) {
		s = s.slice(2, -1);
	}

	let result = "";
	for (let i = 0; i < s.length; i++) {
		if (s[i] !== "\\" || i + 1 >= s.length) {
			result += s[i];
			continue;
		}
		const next = s[i + 1];
		switch (next) {
			case "x": case "X": { // \xHH
				const hex = s.slice(i + 2, i + 4);
				const code = parseInt(hex, 16);
				result += isNaN(code) ? s.slice(i, i + 4) : String.fromCharCode(code);
				i += 3;
				break;
			}
			case "u": { // \uHHHH
				const hex = s.slice(i + 2, i + 6);
				const code = parseInt(hex, 16);
				result += isNaN(code) ? s.slice(i, i + 6) : String.fromCodePoint(code);
				i += 5;
				break;
			}
			case "U": { // \UHHHHHHHH
				const hex = s.slice(i + 2, i + 10);
				const code = parseInt(hex, 16);
				result += isNaN(code) ? s.slice(i, i + 10) : String.fromCodePoint(code);
				i += 9;
				break;
			}
			case "0": case "1": case "2": case "3":
			case "4": case "5": case "6": case "7": { // \NNN octal
				let oct = next;
				if (i + 2 < s.length && s[i + 2] >= "0" && s[i + 2] <= "7") { oct += s[i + 2]; i++; }
				if (i + 2 < s.length && s[i + 2] >= "0" && s[i + 2] <= "7") { oct += s[i + 2]; i++; }
				result += String.fromCharCode(parseInt(oct, 8));
				i++;
				break;
			}
			case "n": result += "\n"; i++; break;
			case "t": result += "\t"; i++; break;
			case "r": result += "\r"; i++; break;
			case "a": result += "\x07"; i++; break;
			case "b": result += "\b"; i++; break;
			case "f": result += "\f"; i++; break;
			case "v": result += "\v"; i++; break;
			case "e": case "E": result += "\x1b"; i++; break;
			case "\\": result += "\\"; i++; break;
			case "'": result += "'"; i++; break;
			case '"': result += '"'; i++; break;
			default: result += "\\" + next; i++; break;
		}
	}
	return result;
}

// ── Command name resolution ─────────────────────────────────────────────

/**
 * Resolve a command_name AST node to a plain string.
 * Returns null if the name is dynamic (variable expansion, command
 * substitution, ANSI-C string, concatenation, etc.).
 */
function resolveCommandName(nameNode: SyntaxNode): string | null {
	if (nameNode.childCount === 0) return null;
	const child = nameNode.child(0);
	if (!child) return null;

	switch (child.type) {
		case "word": {
			let name = child.text;
			// Strip backslash escapes: \rm → rm
			name = name.replace(/\\/g, "");
			// Strip path prefix: /usr/bin/rm → rm
			const slash = name.lastIndexOf("/");
			if (slash !== -1) name = name.substring(slash + 1);
			return name || null;
		}

		case "string": {
			// Double-quoted command name: "rm"
			// Only safe if it's pure static content (no interpolation)
			let content = "";
			let dynamic = false;
			for (let i = 0; i < child.childCount; i++) {
				const sc = child.child(i);
				if (!sc) continue;
				if (sc.type === "string_content") {
					content += sc.text;
				} else if (sc.isNamed) {
					dynamic = true;
					break;
				}
			}
			return dynamic ? null : (content || null);
		}

		case "raw_string": {
			// Single-quoted: 'rm'
			const text = child.text;
			if (text.startsWith("'") && text.endsWith("'")) {
				return text.slice(1, -1) || null;
			}
			return null;
		}

		// Dynamic constructs — cannot resolve statically
		case "command_substitution":   // $(echo rm)
		case "simple_expansion":       // $cmd
		case "expansion":              // ${cmd}
		case "process_substitution":   // <(cmd)
		case "ansi_c_string":          // $'\x72\x6d'
		case "concatenation":          // r""m, "$a"b, etc.
			return null;

		default:
			return null;
	}
}

// ── Argument extraction ─────────────────────────────────────────────────

/** Extract argument text values from a command node */
function getCommandArgs(node: SyntaxNode): string[] {
	const args: string[] = [];
	for (let i = 0; i < node.childCount; i++) {
		const child = node.child(i);
		if (!child || !child.isNamed) continue;
		if (child.type === "command_name") continue;
		if (child.type === "variable_assignment") continue;
		if (child.type === "file_redirect") continue;
		if (child.type === "herestring_redirect") continue;
		if (child.type === "subshell") continue;
		args.push(child.text);
	}
	return args;
}

// ── Command wrapper unwrapping ──────────────────────────────────────────

/**
 * Unwrap benign command wrappers to find the real command.
 * e.g. `env FOO=bar nice -n5 rm file` → command: "rm", args: ["file"]
 */
function unwrapCommand(command: string, args: string[]): { command: string; commandArgs: string[] } {
	if (!BENIGN_WRAPPERS.has(command)) {
		return { command, commandArgs: args };
	}

	let i = 0;

	if (command === "env") {
		// env: skip variable assignments (FOO=bar) and flags
		while (i < args.length) {
			const a = args[i];
			if (a.includes("=") && !a.startsWith("-")) {
				i++; // VAR=value
			} else if (a.startsWith("-")) {
				if ((a === "-u" || a === "--unset") && i + 1 < args.length) i++; // -u takes a value
				i++;
			} else {
				break;
			}
		}
	} else if (command === "timeout") {
		// timeout [FLAGS] DURATION COMMAND [ARGS]
		while (i < args.length && args[i].startsWith("-")) {
			if ((args[i] === "-k" || args[i] === "--kill-after" || args[i] === "-s" || args[i] === "--signal") && i + 1 < args.length) i++;
			i++;
		}
		if (i < args.length) i++; // skip DURATION
	} else {
		// Generic wrapper: skip flags, first non-flag arg is the real command
		while (i < args.length && args[i].startsWith("-")) i++;
	}

	if (i < args.length) {
		let realCmd = args[i];
		// Strip path prefix from the inner command too
		const slash = realCmd.lastIndexOf("/");
		if (slash !== -1) realCmd = realCmd.substring(slash + 1);
		// Recurse in case of stacked wrappers: nice env rm
		return unwrapCommand(realCmd, args.slice(i + 1));
	}

	// No inner command found (e.g., bare `env` prints environment)
	return { command, commandArgs: [] };
}

// ── Redirect classification ─────────────────────────────────────────────

/** Destinations that are safe for output redirects */
const SAFE_REDIRECT_DESTINATIONS = new Set(["/dev/null", "/dev/stdout", "/dev/stderr"]);

function classifyFileRedirect(node: SyntaxNode, reasons: string[]): void {
	let operator = "";
	let destination = "";

	for (let i = 0; i < node.childCount; i++) {
		const child = node.child(i);
		if (!child) continue;

		if (!child.isNamed) {
			const t = child.type;
			// All redirect operators emitted by tree-sitter-bash
			if (t === ">" || t === ">>" || t === ">&" || t === ">|" || t === "&>" || t === "&>>"
				|| t === "<" || t === "<<" || t === "<<<" || t === "<&") {
				operator = t;
			}
		} else if (child.type !== "file_descriptor") {
			destination = child.text;
		}
	}

	// Input redirects are always safe
	if (operator === "<" || operator === "<<" || operator === "<<<" || operator === "<&") return;

	// fd-to-fd redirect like 2>&1 is safe
	if (operator === ">&" && /^\d+$/.test(destination)) return;

	// Output to /dev/null etc. is safe
	if (SAFE_REDIRECT_DESTINATIONS.has(destination) || destination.startsWith("/dev/fd/")) return;

	// Any output redirect → gate
	// >  >>  >&  >|  (clobber) &> (stdout+stderr) &>> (append stdout+stderr)
	const WRITE_OPERATORS = new Set([">", ">>", ">&", ">|", "&>", "&>>"]);
	if (WRITE_OPERATORS.has(operator)) {
		reasons.push(`output redirect \`${operator} ${destination}\` — writes to filesystem`);
	}
}

// ── Regex fallback ──────────────────────────────────────────────────────
// Used when tree-sitter fails to initialize (missing WASM, etc.)

const FALLBACK_PATTERNS = [
	/\brm\b/, /\brmdir\b/, /\bunlink\b/, /\btrash\b/, /\bsrm\b/,
	/\bmv\b/, /\bcp\b/, /\brsync\b/, /\bmkdir\b/,
	/\bchmod\b/, /\bchown\b/, /\btouch\b/, /\bln\b/,
	/\btee\b/, /\bdd\b/, /\bshred\b/, /\btruncate\b/,
	/\bsudo\b/, /\bdoas\b/,
	/\beval\b/, /\bexec\b/, /\bsource\b/,
	/\bpython3?\b.*\b-c\b/, /\bnode\b.*\b-e\b/, /\bruby\b.*\b-e\b/, /\bperl\b.*\b-e\b/,
	/\bnpm\s+(install|i|ci|uninstall|remove|rm|run|start|test|exec)\b/,
	/\bcurl\b.*\b-[oO]\b/, /\bwget\b/,
	/\bsed\b.*\b-i\b/, /\bsort\b.*\b-o\b/,
	/\bfind\b.*(-delete|-exec)\b/,
	/\btar\b.*\b[xc]\b/,
	/\bpatch\b/, /\binstall\b/,
	/[^<]>(?!&)/, />>/, // output redirects
];

const FALLBACK_GIT_REGEX = new RegExp(
	`\\bgit\\s+(?:${["checkout", "reset", "clean", "rebase", "cherry-pick", "merge", "revert",
		"stash", "push", "commit", "add", "rm", "mv", "restore", "switch", "tag", "branch"].join("|")})\\b`,
);

function isGatedFallback(command: string): boolean {
	return FALLBACK_PATTERNS.some(p => p.test(command)) || FALLBACK_GIT_REGEX.test(command);
}
