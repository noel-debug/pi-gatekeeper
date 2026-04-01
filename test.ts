/**
 * Test suite for the gatekeeper AST analyzer.
 * Run with: npx tsx test.ts
 */

import { analyzeCommand } from "./analyzer";

interface TestCase {
	cmd: string;
	expect: "safe" | "gated";
	label?: string;
}

const tests: TestCase[] = [
	// ── Safe: read-only commands ────────────────────────────────────
	{ cmd: "ls -la", expect: "safe" },
	{ cmd: "ls -la /tmp", expect: "safe" },
	{ cmd: "cat file.txt", expect: "safe" },
	{ cmd: "head -20 file.txt", expect: "safe" },
	{ cmd: "tail -f log.txt", expect: "safe" },
	{ cmd: "grep -r 'pattern' src/", expect: "safe" },
	{ cmd: "rg pattern", expect: "safe" },
	{ cmd: "find . -name '*.ts' -type f", expect: "safe" },
	{ cmd: "wc -l file.txt", expect: "safe" },
	{ cmd: "file image.png", expect: "safe" },
	{ cmd: "diff a.txt b.txt", expect: "safe" },
	{ cmd: "echo hello world", expect: "safe" },
	{ cmd: "pwd", expect: "safe" },
	{ cmd: "whoami", expect: "safe" },
	{ cmd: "date", expect: "safe" },
	{ cmd: "which git", expect: "safe" },
	{ cmd: "du -sh .", expect: "safe" },
	{ cmd: "df -h", expect: "safe" },
	{ cmd: "jq '.name' package.json", expect: "safe" },
	{ cmd: "sort input.txt", expect: "safe" },
	{ cmd: "uniq input.txt", expect: "safe" },
	{ cmd: "cut -d: -f1 /etc/passwd", expect: "safe" },
	{ cmd: "tr 'a-z' 'A-Z'", expect: "safe" },
	{ cmd: "sed 's/foo/bar/' file.txt", expect: "safe", label: "sed without -i" },
	{ cmd: "awk '{print $1}' file.txt", expect: "safe" },
	{ cmd: "stat file.txt", expect: "safe" },
	{ cmd: "readlink -f file.txt", expect: "safe" },
	{ cmd: "basename /path/to/file", expect: "safe" },
	{ cmd: "dirname /path/to/file", expect: "safe" },
	{ cmd: "test -f file.txt", expect: "safe" },
	{ cmd: "[ -d /tmp ]", expect: "safe" },
	{ cmd: "sleep 1", expect: "safe" },
	{ cmd: "cd /tmp", expect: "safe" },
	{ cmd: "cd /tmp && ls", expect: "safe" },
	{ cmd: "ping -c 1 google.com", expect: "safe" },
	{ cmd: "dig google.com", expect: "safe" },
	{ cmd: "curl https://example.com", expect: "safe" },
	{ cmd: "curl -s https://api.example.com/data", expect: "safe" },
	{ cmd: "ps aux", expect: "safe" },
	{ cmd: "lsof -i :3000", expect: "safe" },
	{ cmd: "man ls", expect: "safe" },

	// ── Safe: git read-only ─────────────────────────────────────────
	{ cmd: "git status", expect: "safe" },
	{ cmd: "git log --oneline", expect: "safe" },
	{ cmd: "git log --oneline -20", expect: "safe" },
	{ cmd: "git diff", expect: "safe" },
	{ cmd: "git diff HEAD~1", expect: "safe" },
	{ cmd: "git show HEAD", expect: "safe" },
	{ cmd: "git blame file.txt", expect: "safe" },
	{ cmd: "git branch", expect: "safe", label: "git branch list" },
	{ cmd: "git branch -a", expect: "safe", label: "git branch list all" },
	{ cmd: "git tag", expect: "safe", label: "git tag list" },
	{ cmd: "git remote -v", expect: "safe" },
	{ cmd: "git stash list", expect: "safe" },
	{ cmd: "git ls-files", expect: "safe" },
	{ cmd: "git rev-parse HEAD", expect: "safe" },
	{ cmd: "git --no-pager diff", expect: "safe" },
	{ cmd: "git -C /path log", expect: "safe" },
	{ cmd: "git --version", expect: "safe" },

	// ── Safe: version checks ────────────────────────────────────────
	{ cmd: "node --version", expect: "safe" },
	{ cmd: "python3 --version", expect: "safe" },
	{ cmd: "rustc --version", expect: "safe" },
	{ cmd: "go version", expect: "safe" },
	{ cmd: "gcc --version", expect: "safe" },

	// ── Safe: package manager read-only ─────────────────────────────
	{ cmd: "npm ls", expect: "safe" },
	{ cmd: "npm view react version", expect: "safe" },
	{ cmd: "npm outdated", expect: "safe" },
	{ cmd: "npm audit", expect: "safe" },
	{ cmd: "cargo check", expect: "safe" },
	{ cmd: "pip3 list", expect: "safe" },

	// ── Safe: benign wrappers around safe commands ──────────────────
	{ cmd: "env ls", expect: "safe" },
	{ cmd: "env FOO=bar ls -la", expect: "safe" },
	{ cmd: "nice grep pattern file", expect: "safe" },
	{ cmd: "time ls -la", expect: "safe", label: "time wrapping safe cmd" },
	{ cmd: "timeout 5 cat file.txt", expect: "safe" },
	{ cmd: "command -v git", expect: "safe" },
	{ cmd: "command ls -la", expect: "safe", label: "command wrapper" },
	{ cmd: "builtin echo hello", expect: "safe" },
	{ cmd: "nohup cat file.txt", expect: "safe" },

	// ── Safe: harmless redirects ────────────────────────────────────
	{ cmd: "echo foo > /dev/null", expect: "safe" },
	{ cmd: "echo foo > /dev/null 2>&1", expect: "safe" },
	{ cmd: "ls 2>&1", expect: "safe" },
	{ cmd: "echo foo > /dev/stderr", expect: "safe" },
	{ cmd: "cat < input.txt", expect: "safe", label: "input redirect" },

	// ── Safe: compound safe commands ────────────────────────────────
	{ cmd: "cd /tmp && ls -la", expect: "safe" },
	{ cmd: "ls -la || echo 'empty'", expect: "safe" },
	{ cmd: "echo a; echo b; echo c", expect: "safe" },
	{ cmd: "ls -la | grep foo", expect: "safe" },
	{ cmd: "cat file.txt | sort | uniq", expect: "safe" },
	{ cmd: "git diff | head -50", expect: "safe" },
	{ cmd: "if [ -f foo ]; then cat foo; fi", expect: "safe" },

	// ── Safe: variable assignment only ──────────────────────────────
	{ cmd: "FOO=bar", expect: "safe" },
	{ cmd: "export FOO=bar", expect: "safe" },
	{ cmd: "[ $(echo hi) = hi ]", expect: "safe", label: "cmd sub in test with safe cmd" },

	// ── Safe: env prefix on command ─────────────────────────────────
	{ cmd: "ENV=prod cat config.json", expect: "safe" },

	// ── Safe: archive listing ───────────────────────────────────────
	{ cmd: "tar tf archive.tar", expect: "safe" },
	{ cmd: "tar -tf archive.tar.gz", expect: "safe" },
	{ cmd: "zipinfo archive.zip", expect: "safe" },
	{ cmd: "unzip -l archive.zip", expect: "safe" },

	// ── Safe: heredoc input ─────────────────────────────────────────
	{ cmd: "cat <<EOF\nhello world\nEOF", expect: "safe" },

	// ═══════════════════════════════════════════════════════════════
	// GATED: file mutation commands
	// ═══════════════════════════════════════════════════════════════

	// ── Gated: direct mutation ──────────────────────────────────────
	{ cmd: "rm file.txt", expect: "gated" },
	{ cmd: "rm -rf /tmp/foo", expect: "gated" },
	{ cmd: "rmdir empty_dir", expect: "gated" },
	{ cmd: "mv old.txt new.txt", expect: "gated" },
	{ cmd: "cp src.txt dst.txt", expect: "gated" },
	{ cmd: "mkdir -p new_dir", expect: "gated" },
	{ cmd: "touch new_file.txt", expect: "gated" },
	{ cmd: "chmod +x script.sh", expect: "gated" },
	{ cmd: "chown user:group file.txt", expect: "gated" },
	{ cmd: "ln -s target link", expect: "gated" },
	{ cmd: "truncate -s 0 file.txt", expect: "gated" },
	{ cmd: "shred file.txt", expect: "gated" },
	{ cmd: "dd if=/dev/zero of=file bs=1M count=1", expect: "gated" },
	{ cmd: "rsync -av src/ dst/", expect: "gated" },
	{ cmd: "install src dest", expect: "gated" },
	{ cmd: "patch < diff.patch", expect: "gated" },

	// ── Gated: write tools ──────────────────────────────────────────
	{ cmd: "echo foo | tee output.txt", expect: "gated" },
	{ cmd: "tee output.txt", expect: "gated" },

	// ── Gated: output redirects ─────────────────────────────────────
	{ cmd: "echo foo > bar.txt", expect: "gated" },
	{ cmd: "echo foo >> bar.txt", expect: "gated" },
	{ cmd: "cat file > output.txt", expect: "gated" },
	{ cmd: "cat <<EOF > output.txt\nhello\nEOF", expect: "gated", label: "heredoc with file redirect" },

	// ── Gated: sed -i / sort -o ─────────────────────────────────────
	{ cmd: "sed -i 's/foo/bar/' file.txt", expect: "gated" },
	{ cmd: "sed --in-place 's/foo/bar/' file.txt", expect: "gated" },
	{ cmd: "sort -o output.txt input.txt", expect: "gated" },

	// ── Gated: find with mutation ───────────────────────────────────
	{ cmd: "find . -name '*.tmp' -delete", expect: "gated" },
	{ cmd: "find . -exec rm {} \\;", expect: "gated" },

	// ── Gated: curl/wget writing ────────────────────────────────────
	{ cmd: "curl -o output.txt https://example.com", expect: "gated" },
	{ cmd: "curl -O https://example.com/file", expect: "gated" },
	{ cmd: "wget https://example.com", expect: "gated" },

	// ── Gated: archive extraction ───────────────────────────────────
	{ cmd: "tar xf archive.tar", expect: "gated" },
	{ cmd: "tar -xzf archive.tar.gz", expect: "gated" },
	{ cmd: "unzip archive.zip", expect: "gated" },

	// ── Gated: git mutation ─────────────────────────────────────────
	{ cmd: "git push origin main", expect: "gated" },
	{ cmd: "git commit -m 'msg'", expect: "gated" },
	{ cmd: "git add .", expect: "gated" },
	{ cmd: "git checkout branch", expect: "gated" },
	{ cmd: "git reset --hard", expect: "gated" },
	{ cmd: "git rebase main", expect: "gated" },
	{ cmd: "git merge feature", expect: "gated" },
	{ cmd: "git stash", expect: "gated" },
	{ cmd: "git branch new-branch", expect: "gated", label: "git branch create" },
	{ cmd: "git tag v1.0", expect: "gated", label: "git tag create" },

	// ── Gated: npm mutation ─────────────────────────────────────────
	{ cmd: "npm install", expect: "gated" },
	{ cmd: "npm install react", expect: "gated" },
	{ cmd: "npm run build", expect: "gated" },
	{ cmd: "npm test", expect: "gated" },
	{ cmd: "npm start", expect: "gated" },

	// ── Gated: privilege escalation ─────────────────────────────────
	{ cmd: "sudo rm file", expect: "gated" },
	{ cmd: "sudo apt install foo", expect: "gated" },
	{ cmd: "doas rm file", expect: "gated" },

	// ── Gated: shell execution ──────────────────────────────────────
	{ cmd: "bash -c 'rm file'", expect: "gated" },
	{ cmd: "sh -c 'rm file'", expect: "gated" },
	{ cmd: "bash script.sh", expect: "gated" },
	{ cmd: "source script.sh", expect: "gated" },
	{ cmd: ". script.sh", expect: "gated" },
	{ cmd: "eval 'rm file'", expect: "gated" },
	{ cmd: "exec rm file", expect: "gated" },

	// ── Gated: interpreters with code ───────────────────────────────
	{ cmd: "python3 -c 'import os; os.remove(\"f\")'", expect: "gated" },
	{ cmd: "node -e 'require(\"fs\").unlinkSync(\"f\")'", expect: "gated" },
	{ cmd: "ruby -e 'File.delete(\"f\")'", expect: "gated" },
	{ cmd: "perl -e 'unlink \"f\"'", expect: "gated" },
	{ cmd: "python3 script.py", expect: "gated" },

	// ── Gated: process control ──────────────────────────────────────
	{ cmd: "kill 1234", expect: "gated" },
	{ cmd: "killall node", expect: "gated" },
	{ cmd: "pkill node", expect: "gated" },

	// ── Gated: xargs (runs arbitrary commands) ──────────────────────
	{ cmd: "echo file.txt | xargs rm", expect: "gated" },
	{ cmd: "xargs rm < list.txt", expect: "gated" },

	// ═══════════════════════════════════════════════════════════════
	// GATED: obfuscation / evasion attempts
	// ═══════════════════════════════════════════════════════════════

	{ cmd: "$(echo rm) file.txt", expect: "gated", label: "command substitution in cmd position" },
	{ cmd: "a=rm; $a file", expect: "gated", label: "variable expansion in cmd position" },
	{ cmd: "$'\\x72\\x6d' file", expect: "gated", label: "ANSI-C string in cmd position" },
	{ cmd: "/bin/rm file", expect: "gated", label: "absolute path to rm" },
	{ cmd: "/usr/bin/env rm file", expect: "gated", label: "env wrapping rm" },
	{ cmd: "\\rm file", expect: "gated", label: "backslash-escaped rm" },
	{ cmd: "'rm' file", expect: "gated", label: "single-quoted rm" },
	{ cmd: '"rm" file', expect: "gated", label: "double-quoted rm" },
	{ cmd: "echo cm0= | base64 -d | sh", expect: "gated", label: "base64 piped to sh" },
	{ cmd: "nice rm file", expect: "gated", label: "nice wrapping rm" },
	{ cmd: "env rm file", expect: "gated", label: "env wrapping rm" },
	{ cmd: "nohup rm file &", expect: "gated", label: "nohup wrapping rm" },
	{ cmd: "command rm file", expect: "gated", label: "command wrapping rm" },
	{ cmd: "builtin rm file", expect: "gated", label: "builtin wrapping rm" },
	{ cmd: "for f in *.txt; do rm \"$f\"; done", expect: "gated", label: "rm inside for loop" },

	// ── Gated: awk/sed internal file writes ───────────────────────
	{ cmd: "awk 'BEGIN{print \"x\" > \"/tmp/f\"}'", expect: "gated", label: "awk internal > redirect" },
	{ cmd: "awk '{print >> \"/tmp/f\"}' input", expect: "gated", label: "awk internal >> redirect" },
	{ cmd: "awk 'BEGIN{system(\"rm file\");}'", expect: "gated", label: "awk system() call" },
	{ cmd: "sed -n 'w /tmp/file' input", expect: "gated", label: "sed w command" },
	{ cmd: "awk '{print $1}' file.txt", expect: "safe", label: "awk normal usage" },
	{ cmd: "sed 's/foo/bar/' file.txt", expect: "safe", label: "sed normal usage" },
	{ cmd: "while true; do rm file; done", expect: "gated", label: "rm inside while loop" },
	{ cmd: "if true; then rm file; fi", expect: "gated", label: "rm inside if" },
	{ cmd: "echo safe; rm dangerous", expect: "gated", label: "rm after semicolon" },
	{ cmd: "echo safe && rm dangerous", expect: "gated", label: "rm after &&" },

	// ── Gated: stacked wrappers ─────────────────────────────────────
	{ cmd: "nice env nohup rm file", expect: "gated", label: "stacked wrappers around rm" },
	{ cmd: "env FOO=bar nice -n5 rm -rf /tmp/test", expect: "gated", label: "env+nice wrapping rm" },

	// ── Gated: command substitution in arguments (P1) ─────────
	{ cmd: "echo $(rm file)", expect: "gated", label: "cmd sub in safe command arg" },
	{ cmd: "grep $(rm /etc/shadow) pattern", expect: "gated", label: "dangerous cmd sub in grep arg" },
	{ cmd: 'echo "hello $(touch /tmp/pwned)"', expect: "gated", label: "cmd sub in string arg" },
	{ cmd: "true $(rm file)", expect: "gated", label: "cmd sub in true arg" },

	// ── Gated: variable assignment with command substitution (P1) ──
	{ cmd: "FOO=$(rm file)", expect: "gated", label: "var assign with cmd sub" },
	{ cmd: "A=$(touch /tmp/x)", expect: "gated", label: "var assign with touch" },
	{ cmd: "export BAR=$(rm file)", expect: "gated", label: "export with cmd sub" },
	{ cmd: "FOO=$(rm file) echo hi", expect: "gated", label: "env prefix cmd sub" },

	// ── Gated: time as wrapper (P2) ─────────────────────────
	{ cmd: "time rm file", expect: "gated", label: "time wrapping rm" },
	{ cmd: "time touch /tmp/pwned", expect: "gated", label: "time wrapping touch" },
	{ cmd: "time npm install", expect: "gated", label: "time wrapping npm install" },

	// ── Gated: npm pack (P2) ────────────────────────────
	{ cmd: "npm pack", expect: "gated", label: "npm pack creates tarball" },

	// ── Gated: redirect operators >|, &>, &>> (P1) ────────────────
	{ cmd: "echo hi >| out.txt", expect: "gated", label: ">| clobber redirect" },
	{ cmd: "echo hi &> out.txt", expect: "gated", label: "&> stdout+stderr redirect" },
	{ cmd: "echo hi &>> out.txt", expect: "gated", label: "&>> append stdout+stderr" },

	// ── Gated: git branch flag-only mutations (P2) ────────────────
	{ cmd: "git branch --set-upstream-to=origin/main", expect: "gated", label: "git branch set upstream" },
	{ cmd: "git branch --unset-upstream", expect: "gated", label: "git branch unset upstream" },
	{ cmd: "git branch --edit-description", expect: "gated", label: "git branch edit desc" },
	{ cmd: "git branch -d feature", expect: "gated", label: "git branch delete" },
	{ cmd: "git branch -D feature", expect: "gated", label: "git branch force delete" },
	{ cmd: "git branch -m old new", expect: "gated", label: "git branch rename" },
	{ cmd: "git branch -c old new", expect: "gated", label: "git branch copy" },

	// ── Gated: function definition ──────────────────────────────────
	{ cmd: "foo() { rm file; }", expect: "gated", label: "function definition" },
];

async function main() {
	let passed = 0;
	let failed = 0;
	const failures: string[] = [];

	for (const t of tests) {
		const result = await analyzeCommand(t.cmd);
		const actual = result.gated ? "gated" : "safe";
		const ok = actual === t.expect;

		if (ok) {
			passed++;
		} else {
			failed++;
			const label = t.label ? ` (${t.label})` : "";
			const reasonStr = result.reasons.length > 0 ? ` [${result.reasons.join("; ")}]` : "";
			failures.push(`  ✗ Expected ${t.expect}, got ${actual}: ${t.cmd}${label}${reasonStr}`);
		}
	}

	console.log(`\n${"═".repeat(60)}`);
	console.log(`  Results: ${passed} passed, ${failed} failed, ${tests.length} total`);
	console.log("═".repeat(60));

	if (failures.length > 0) {
		console.log("\nFailures:");
		for (const f of failures) console.log(f);
	}

	console.log();
	process.exit(failed > 0 ? 1 : 0);
}

main();
