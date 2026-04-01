/** Tools that always require approval */
export const MUTATING_TOOLS = new Set(["edit", "write"]);

/** Bash command patterns that require approval */
const GATED_BASH_PATTERNS = [
	/\brm\b/,
	/\brmdir\b/,
	/\bunlink\b/,
	/\btrash\b/,
	/\bsrm\b/,
	/\bmv\b/,
	/\bcp\b/,
	/\brsync\b/,
	/\bmkdir\b/,
	/\bchmod\b/,
	/\bchown\b/,
	/\btouch\b/,
	/\bln\b/,
	/\btee\b/,
	/\bdd\b/,
	/\bshred\b/,
	/\btruncate\b/,
];

export function isGatedBashCommand(command: string): boolean {
	return GATED_BASH_PATTERNS.some((p) => p.test(command));
}

/** Build a human-readable summary of a tool call */
export function buildToolSummary(toolName: string, input: Record<string, unknown>): string {
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
