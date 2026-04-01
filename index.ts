/**
 * Gatekeeper Extension
 *
 * Adds a permission system to pi. By default, every file-mutating tool call
 * (edit, write, bash) requires user approval before execution.
 *
 * Consent dialog options:
 *   Yes (y)          – Allow this tool call
 *   No  (n)          – Block this tool call
 *   Tab on Yes/No    – Expand an editor to attach a message to the decision
 *   Auto-accept (a)  – Stop asking and allow all tool calls until toggled back
 *
 * Commands:
 *   /gatekeeper       – Toggle between "ask" (default) and "auto-accept" mode
 *
 * Status indicator in footer shows current mode.
 */

import type { ExtensionAPI, ExtensionContext } from "@mariozechner/pi-coding-agent";
import { Editor, type EditorTheme, Key, matchesKey, truncateToWidth, visibleWidth } from "@mariozechner/pi-tui";

// Which tools require approval
const MUTATING_TOOLS = new Set(["edit", "write"]);

// Patterns that indicate file/folder mutations in bash
const GATED_BASH_PATTERNS = [
	/\brm\b/,
	/\brmdir\b/,
	/\bunlink\b/,
	/\btrash\b/,
	/\bsrm\b/,
	/\bmv\b/,
	/\bcp\b/,
	/\brsync\b/,
];

function isGatedBashCommand(command: string): boolean {
	return GATED_BASH_PATTERNS.some((p) => p.test(command));
}

type ConsentMode = "ask" | "auto-accept";

interface ConsentResult {
	allowed: boolean;
	message?: string;
}

export default function gatekeeper(pi: ExtensionAPI) {
	let mode: ConsentMode = "ask";

	// ── Status indicator ──────────────────────────────────────────────
	function updateStatus(ctx: ExtensionContext) {
		const theme = ctx.ui.theme;
		if (mode === "auto-accept") {
			ctx.ui.setStatus("gatekeeper", theme.fg("warning", "⚡ auto-accept"));
		} else {
			ctx.ui.setStatus("gatekeeper", theme.fg("dim", "● gatekeeper"));
		}
	}

	// ── Restore state from session ────────────────────────────────────
	function restoreState(ctx: ExtensionContext) {
		for (const entry of ctx.sessionManager.getBranch()) {
			if (entry.type === "custom" && entry.customType === "gatekeeper-config") {
				const data = entry.data as { mode?: ConsentMode } | undefined;
				if (data?.mode) mode = data.mode;
			}
		}
		updateStatus(ctx);
	}

	function persistState() {
		pi.appendEntry("gatekeeper-config", { mode });
	}

	// ── Session lifecycle ─────────────────────────────────────────────
	pi.on("session_start", async (_event, ctx) => {
		restoreState(ctx);
	});

	pi.on("session_tree", async (_event, ctx) => {
		restoreState(ctx);
	});

	pi.on("session_fork", async (_event, ctx) => {
		restoreState(ctx);
	});

	pi.on("session_switch", async (_event, ctx) => {
		updateStatus(ctx);
	});

	// ── /gatekeeper command ──────────────────────────────────────────────
	pi.registerCommand("gatekeeper", {
		description: "Toggle gatekeeper mode (ask / auto-accept)",
		handler: async (_args, ctx) => {
			if (mode === "ask") {
				mode = "auto-accept";
				ctx.ui.notify("Gatekeeper: auto-accept (file changes allowed without asking)", "warning");
			} else {
				mode = "ask";
				ctx.ui.notify("Gatekeeper: ask (file changes require approval)", "info");
			}
			persistState();
			updateStatus(ctx);
		},
	});

	// ── Tool call interception ────────────────────────────────────────
	pi.on("tool_call", async (event, ctx) => {
		// Check if this tool call needs approval
		const needsConsent = MUTATING_TOOLS.has(event.toolName)
			|| (event.toolName === "bash" && isGatedBashCommand(event.input.command as string));
		if (!needsConsent) return undefined;

		// Auto-accept mode: allow everything
		if (mode === "auto-accept") return undefined;

		// Non-interactive: block by default
		if (!ctx.hasUI) {
			return { block: true, reason: "Gatekeeper: approval required (no UI available)" };
		}

		// Build a summary of what the tool wants to do
		const summary = buildToolSummary(event.toolName, event.input);

		// Show gatekeeper dialog
		const result = await showConsentDialog(ctx, event.toolName, summary);

		if (result === "auto-accept") {
			mode = "auto-accept";
			persistState();
			updateStatus(ctx);
			return undefined;
		}

		if (result.allowed) {
			if (result.message) {
				pi.sendMessage({
					customType: "gatekeeper-feedback",
					content: result.message,
					display: true,
				});
			}
			return undefined;
		}

		// Blocked
		const reason = result.message
			? `Declined by user: ${result.message}`
			: "Declined by user";

		if (result.message) {
			pi.sendMessage({
				customType: "gatekeeper-feedback",
				content: result.message,
				display: true,
			});
		}

		return { block: true, reason };
	});

	// ── Build summary ─────────────────────────────────────────────────
	function buildToolSummary(toolName: string, input: Record<string, unknown>): string {
		switch (toolName) {
			case "write": {
				const path = input.path as string;
				const content = input.content as string;
				const lines = content?.split("\n").length ?? 0;
				return `Write ${path} (${lines} lines)\n\n${content}`;
			}
			case "edit": {
				const path = input.path as string;
				const edits = input.edits as Array<{ oldText: string; newText: string }> | undefined;
				const count = edits?.length ?? 1;
				let summary = `Edit ${path} (${count} edit${count !== 1 ? "s" : ""})`;
				if (edits) {
					for (let i = 0; i < edits.length; i++) {
						const e = edits[i];
						if (count > 1) summary += `\n\n── edit ${i + 1} ──`;
						else summary += "\n";
						const oldLines = e.oldText.split("\n");
						const newLines = e.newText.split("\n");
						for (const line of oldLines) summary += `\n- ${line}`;
						for (const line of newLines) summary += `\n+ ${line}`;
					}
				}
				return summary;
			}
			case "bash": {
				const command = input.command as string;
				return command;
			}
			default:
				return `${toolName}: ${JSON.stringify(input).slice(0, 120)}`;
		}
	}

	// ── Consent dialog ────────────────────────────────────────────────
	async function showConsentDialog(
		ctx: ExtensionContext,
		toolName: string,
		summary: string,
	): Promise<ConsentResult | "auto-accept"> {
		return ctx.ui.custom<ConsentResult | "auto-accept">((tui, theme, _kb, done) => {
			// State
			let selected = 0; // 0=Yes, 1=No, 2=Auto-accept
			const options = ["Yes", "No", "Auto-accept"];
			let editorOpen = false;
			let editorForOption = 0; // which option the editor is open for
			let cachedLines: string[] | undefined;

			// Editor for attaching a message
			const editorTheme: EditorTheme = {
				borderColor: (s) => theme.fg("accent", s),
				selectList: {
					selectedPrefix: (t) => theme.fg("accent", t),
					selectedText: (t) => theme.fg("accent", t),
					description: (t) => theme.fg("muted", t),
					scrollInfo: (t) => theme.fg("dim", t),
					noMatch: (t) => theme.fg("warning", t),
				},
			};
			const editor = new Editor(tui, editorTheme);

			editor.onSubmit = (value) => {
				const msg = value.trim() || undefined;
				if (editorForOption === 0) {
					done({ allowed: true, message: msg });
				} else {
					done({ allowed: false, message: msg });
				}
			};

			function refresh() {
				cachedLines = undefined;
				tui.requestRender();
			}

			function handleInput(data: string) {
				// Editor mode
				if (editorOpen) {
					if (matchesKey(data, Key.escape)) {
						editorOpen = false;
						editor.setText("");
						refresh();
						return;
					}
					editor.handleInput(data);
					refresh();
					return;
				}

				// Navigation
				if (matchesKey(data, Key.left) || matchesKey(data, Key.up)) {
					selected = (selected - 1 + options.length) % options.length;
					refresh();
					return;
				}
				if (matchesKey(data, Key.right) || matchesKey(data, Key.down)) {
					selected = (selected + 1) % options.length;
					refresh();
					return;
				}

				// Quick keys
				if (data === "y" || data === "Y") {
					done({ allowed: true });
					return;
				}
				if (data === "n" || data === "N") {
					done({ allowed: false });
					return;
				}
				if (data === "a" || data === "A") {
					done("auto-accept");
					return;
				}

				// Tab – open editor to attach a message (only for Yes/No)
				if (matchesKey(data, Key.tab)) {
					if (selected <= 1) {
						editorOpen = true;
						editorForOption = selected;
						editor.setText("");
						refresh();
					}
					return;
				}

				// Enter – confirm selection
				if (matchesKey(data, Key.enter)) {
					if (selected === 0) {
						done({ allowed: true });
					} else if (selected === 1) {
						done({ allowed: false });
					} else {
						done("auto-accept");
					}
					return;
				}

				// Escape – decline
				if (matchesKey(data, Key.escape)) {
					done({ allowed: false });
					return;
				}
			}

			function render(width: number): string[] {
				if (cachedLines) return cachedLines;

				const lines: string[] = [];
				const border = theme.fg("accent", "─".repeat(width));

				lines.push(border);

				// Title
				const toolLabel = toolName.charAt(0).toUpperCase() + toolName.slice(1);
				lines.push(truncateToWidth(` ${theme.fg("accent", theme.bold(`Allow ${toolLabel}?`))}`, width));
				lines.push("");

				// Summary with diff coloring
				const summaryLines = summary.split("\n");
				for (const sl of summaryLines) {
					let color: string;
					if (sl.startsWith("+ ")) {
						color = "toolDiffAdded";
					} else if (sl.startsWith("- ")) {
						color = "toolDiffRemoved";
					} else if (sl.startsWith("── ")) {
						color = "accent";
					} else {
						color = "muted";
					}
					lines.push(truncateToWidth(`  ${theme.fg(color as any, sl)}`, width));
				}

				lines.push("");

				if (editorOpen) {
					const label = editorForOption === 0 ? "Yes" : "No";
					lines.push(truncateToWidth(` ${theme.fg("text", `${label} with message:`)}`, width));
					for (const line of editor.render(width - 2)) {
						lines.push(truncateToWidth(` ${line}`, width));
					}
					lines.push("");
					lines.push(truncateToWidth(` ${theme.fg("dim", "Enter to submit • Esc to go back")}`, width));
				} else {
					// Option buttons
					const parts: string[] = [];
					for (let i = 0; i < options.length; i++) {
						const label = ` ${options[i]} `;
						if (i === selected) {
							parts.push(theme.bg("selectedBg", theme.fg("text", label)));
						} else {
							parts.push(theme.fg("dim", label));
						}
					}
					lines.push(truncateToWidth(` ${parts.join("  ")}`, width));

					lines.push("");
					lines.push(truncateToWidth(
						` ${theme.fg("dim", "←→ navigate • y/n/a quick-pick • Tab add message • Enter confirm")}`,
						width,
					));
				}

				lines.push(border);

				cachedLines = lines;
				return lines;
			}

			return {
				render,
				invalidate: () => { cachedLines = undefined; },
				handleInput,
			};
		});
	}
}
