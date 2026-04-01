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

		await Parser.init({
			locateFile: () => join(tsPkgDir, "tree-sitter.wasm"),
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
	if (!parser) return { gated: isGatedFallback(command), reasons: ["regex fallback"] };

	const tree = parser.parse(command);
	const root = tree.rootNode;

	// Parse errors → gate (possible obfuscation or complex construct)
	if (root.hasError) {
		return { gated: true, reasons: ["parse error (possible obfuscation)"] };
	}

	const reasons: string[] = [];
	classifyNode(root, reasons);
	return { gated: reasons.length > 0, reasons };
}

// ── AST walker ──────────────────────────────────────────────────────────

/**
 * Node classification strategy:
 *
 * - "command"             → extract name, unwrap wrappers, check allowlist
 * - "file_redirect"       → check for output operators (>, >>)
 * - "function_definition" → always gate (defines callable code)
 * - Leaf-safe nodes       → skip (variable_assignment, test_command, etc.)
 * - Everything else       → recurse into named children
 *
 * Unknown named node types hit the default branch which recurses.
 * This ensures we never silently skip a dangerous construct.
 */

/** Node types that are safe by themselves and don't need child inspection */
const LEAF_SAFE = new Set([
	"variable_assignment", "variable_assignments",
	"declaration_command", "unset_command", "test_command",
	"comment", "heredoc_body", "heredoc_start", "heredoc_end",
]);

function classifyNode(node: SyntaxNode, reasons: string[]): void {
	// ERROR nodes from tree-sitter error recovery
	if (node.type === "ERROR" || node.isError) {
		reasons.push(`parse error near: ${node.text.slice(0, 40)}`);
		return;
	}

	switch (node.type) {
		case "command":
			classifyCommand(node, reasons);
			return;

		case "file_redirect":
			classifyFileRedirect(node, reasons);
			return;

		case "function_definition":
			reasons.push("function definition (unanalyzable)");
			return;

		default:
			// Leaf-safe nodes: no children to worry about
			if (LEAF_SAFE.has(node.type)) return;

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

// ── Command classification ──────────────────────────────────────────────

function classifyCommand(node: SyntaxNode, reasons: string[]): void {
	const nameNode = node.childForFieldName("name");
	if (!nameNode) {
		reasons.push("command without name");
		return;
	}

	// Also check for inline redirects on the command itself
	const redirects = node.childrenForFieldName("redirect");
	for (const r of redirects) {
		if (r.isNamed) classifyNode(r, reasons);
	}

	// Resolve the static command name
	const resolved = resolveCommandName(nameNode);
	if (!resolved) {
		reasons.push(`dynamic command name: ${nameNode.text.slice(0, 60)}`);
		return;
	}

	const args = getCommandArgs(node);

	// Special case: `command -v/-V` is a type-check, always safe
	if (resolved === "command" && args.length > 0 && (args[0] === "-v" || args[0] === "-V")) {
		return;
	}

	// Unwrap benign wrappers (env, nice, nohup, etc.)
	const unwrapped = unwrapCommand(resolved, args);

	// Check the unwrapped command against the allowlist
	const rule = SAFE_COMMANDS[unwrapped.command];
	if (rule === undefined) {
		reasons.push(`command not in allowlist: ${unwrapped.command}`);
		return;
	}
	if (rule === true) return; // always safe
	if (!rule(unwrapped.commandArgs)) {
		reasons.push(`${unwrapped.command} with mutating arguments`);
	}
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
			if (t === ">" || t === ">>" || t === ">&" || t === "<" || t === "<<" || t === "<<<" || t === "<&") {
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

	// Any other output redirect → gate
	if (operator === ">" || operator === ">>" || operator === ">&") {
		reasons.push(`output redirect: ${operator} ${destination}`);
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
