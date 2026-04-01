/**
 * Public API for command classification.
 *
 * Delegates to the tree-sitter AST analyzer with regex fallback.
 */

import { analyzeCommand, type AnalysisResult } from "./analyzer";

/** Tools that always require approval (regardless of arguments) */
export const MUTATING_TOOLS = new Set(["edit", "write"]);

/**
 * Analyze a bash command and return whether it should be gated.
 *
 * Uses tree-sitter-bash for structural analysis with a default-deny
 * allowlist. Falls back to regex patterns if tree-sitter is unavailable.
 */
export async function isGatedBashCommand(command: string): Promise<boolean> {
	const result = await analyzeCommand(command);
	return result.gated;
}

/**
 * Analyze a bash command and return detailed classification results.
 * Includes human-readable reasons for why a command was gated.
 */
export { analyzeCommand, type AnalysisResult };

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
