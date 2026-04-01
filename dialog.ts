import type { ExtensionContext } from "@mariozechner/pi-coding-agent";
import { Editor, type EditorTheme, Key, matchesKey, truncateToWidth } from "@mariozechner/pi-tui";

export interface ConsentResult {
	allowed: boolean;
	message?: string;
}

export async function showGatekeeperDialog(
	ctx: ExtensionContext,
	toolName: string,
	summary: string,
	detectionReasons?: string[],
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

			// Detection reasons (when enabled)
			if (detectionReasons && detectionReasons.length > 0) {
				lines.push("");
				lines.push(truncateToWidth(`  ${theme.fg("warning", "Gated because:")}`, width));
				for (const reason of detectionReasons) {
					lines.push(truncateToWidth(`  ${theme.fg("warning", `• ${reason}`)}`, width));
				}
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
