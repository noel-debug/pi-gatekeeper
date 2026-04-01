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
 *   /gatekeeper       – Open settings (mode, show detection reasons)
 *
 * Status indicator in footer shows current mode.
 */

import type { ExtensionAPI, ExtensionContext } from "@mariozechner/pi-coding-agent";
import { getSettingsListTheme } from "@mariozechner/pi-coding-agent";
import { Container, type SettingItem, SettingsList, Text } from "@mariozechner/pi-tui";
import { showGatekeeperDialog } from "./dialog";
import { analyzeCommand, buildToolSummary, MUTATING_TOOLS } from "./patterns";

type ConsentMode = "ask" | "auto-accept";

export default function gatekeeper(pi: ExtensionAPI) {
	let mode: ConsentMode = "ask";
	let showReasons = false;

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
				const data = entry.data as { mode?: ConsentMode; showReasons?: boolean } | undefined;
				if (data?.mode) mode = data.mode;
				if (data?.showReasons !== undefined) showReasons = data.showReasons;
			}
		}
		updateStatus(ctx);
	}

	function persistState() {
		pi.appendEntry("gatekeeper-config", { mode, showReasons });
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
		description: "Gatekeeper settings",
		handler: async (_args, ctx) => {
			await ctx.ui.custom((tui, theme, _kb, done) => {
				const items: SettingItem[] = [
					{ id: "mode", label: "Mode", currentValue: mode, values: ["ask", "auto-accept"] },
					{ id: "showReasons", label: "Show detection reasons", currentValue: showReasons ? "on" : "off", values: ["on", "off"] },
				];

				const container = new Container();
				container.addChild(new Text(theme.fg("accent", theme.bold("Gatekeeper Settings")), 1, 1));

				const settingsList = new SettingsList(
					items,
					items.length + 2,
					getSettingsListTheme(),
					(id, newValue) => {
						if (id === "mode") {
							mode = newValue as ConsentMode;
							updateStatus(ctx);
						} else if (id === "showReasons") {
							showReasons = newValue === "on";
						}
						persistState();
					},
					() => done(undefined),
				);
				container.addChild(settingsList);

				return {
					render: (w: number) => container.render(w),
					invalidate: () => container.invalidate(),
					handleInput: (data: string) => {
						settingsList.handleInput?.(data);
						tui.requestRender();
					},
				};
			});
		},
	});

	// ── Tool call interception ────────────────────────────────────────
	pi.on("tool_call", async (event, ctx) => {
		// Check if this tool call needs approval
		let needsApproval = MUTATING_TOOLS.has(event.toolName);
		let detectionReasons: string[] | undefined;

		if (!needsApproval && event.toolName === "bash") {
			const analysis = await analyzeCommand(event.input.command as string);
			needsApproval = analysis.gated;
			detectionReasons = analysis.reasons;
		}

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
		const reasons = showReasons ? detectionReasons : undefined;
		const result = await showGatekeeperDialog(ctx, event.toolName, summary, reasons);

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
