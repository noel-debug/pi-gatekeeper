/**
 * Gatekeeper Extension
 *
 * Adds a permission system to pi. By default, every file-mutating tool call
 * (edit, write, destructive bash) requires user approval before execution.
 *
 * Dialog options:
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
import { showGatekeeperDialog } from "./dialog";
import { buildToolSummary, isGatedBashCommand, MUTATING_TOOLS } from "./patterns";

type ConsentMode = "ask" | "auto-accept";

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
			if (entry.type === "custom" && (entry.customType === "gatekeeper-config" || entry.customType === "consent-config")) {
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

	// ── /gatekeeper command ───────────────────────────────────────────
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
		const needsApproval = MUTATING_TOOLS.has(event.toolName)
			|| (event.toolName === "bash" && await isGatedBashCommand(event.input.command as string));
		if (!needsApproval) return undefined;

		// Auto-accept mode: allow everything
		if (mode === "auto-accept") return undefined;

		// Non-interactive: block by default
		if (!ctx.hasUI) {
			return { block: true, reason: "Gatekeeper: approval required (no UI available)" };
		}

		// Build a summary of what the tool wants to do
		const summary = buildToolSummary(event.toolName, event.input);

		// Show gatekeeper dialog
		const result = await showGatekeeperDialog(ctx, event.toolName, summary);

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
}
