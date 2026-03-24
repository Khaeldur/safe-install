import * as vscode from 'vscode';
import { SafeInstallBridge } from './safeInstallBridge';

export class PackageHoverProvider implements vscode.HoverProvider {
	constructor(private bridge: SafeInstallBridge) {}

	async provideHover(
		document: vscode.TextDocument,
		position: vscode.Position,
		token: vscode.CancellationToken
	): Promise<vscode.Hover | null> {
		const fileName = document.fileName.split(/[\\/]/).pop() || '';
		const ecosystem = this.detectEcosystem(fileName);
		if (!ecosystem) return null;

		const line = document.lineAt(position.line).text;
		const pkg = this.extractPackageName(line, ecosystem);
		if (!pkg) return null;

		const pkgStart = line.indexOf(pkg);
		const pkgEnd = pkgStart + pkg.length;
		if (position.character < pkgStart || position.character > pkgEnd) return null;

		if (token.isCancellationRequested) return null;

		try {
			const intel = await this.bridge.getIntelligence(pkg, ecosystem);
			if (token.isCancellationRequested) return null;

			const md = new vscode.MarkdownString();
			md.isTrusted = true;

			md.appendMarkdown(`### $(shield) Safe Install: \`${pkg}\`\n\n`);

			if (intel.age) {
				md.appendMarkdown(`**Age:** ${intel.age}\n\n`);
			}

			if (intel.typosquatRisk !== undefined) {
				const risk = intel.typosquatRisk;
				const icon = risk === 'high' ? '$(error)' : risk === 'medium' ? '$(warning)' : '$(pass)';
				md.appendMarkdown(`**Typosquat Risk:** ${icon} ${risk}\n\n`);
			}

			if (intel.maintainers) {
				const count = Array.isArray(intel.maintainers) ? intel.maintainers.length : intel.maintainers;
				md.appendMarkdown(`**Maintainers:** ${count}\n\n`);
			}

			if (intel.downloads) {
				md.appendMarkdown(`**Downloads:** ${intel.downloads}\n\n`);
			}

			if (intel.riskScore !== undefined) {
				const score = intel.riskScore;
				const bar = score <= 3 ? '$(pass)' : score <= 6 ? '$(warning)' : '$(error)';
				md.appendMarkdown(`**Risk Score:** ${bar} ${score}/10\n\n`);
			}

			if (intel.findings && intel.findings.length > 0) {
				md.appendMarkdown(`**Findings:**\n`);
				for (const f of intel.findings) {
					md.appendMarkdown(`- ${f.severity}: ${f.message}\n`);
				}
			}

			const range = new vscode.Range(
				position.line, pkgStart,
				position.line, pkgEnd
			);
			return new vscode.Hover(md, range);
		} catch {
			return null;
		}
	}

	private extractPackageName(line: string, ecosystem: string): string | null {
		if (ecosystem === 'pypi') {
			const trimmed = line.trim();
			if (trimmed.startsWith('#') || trimmed.startsWith('-')) return null;
			const match = trimmed.match(/^([a-zA-Z0-9_-][a-zA-Z0-9._-]*)/);
			return match ? match[1] : null;
		}

		if (ecosystem === 'npm') {
			const match = line.match(/"(@?[a-zA-Z0-9._/-]+)"\s*:/);
			return match ? match[1] : null;
		}

		if (ecosystem === 'crates') {
			const match = line.match(/^([a-zA-Z0-9_-]+)\s*=/);
			return match ? match[1] : null;
		}

		if (ecosystem === 'go') {
			const match = line.match(/^\s+([\w./-]+)\s+v/);
			return match ? match[1] : null;
		}

		if (ecosystem === 'rubygems') {
			const match = line.match(/gem\s+['"]([a-zA-Z0-9_-]+)['"]/);
			return match ? match[1] : null;
		}

		return null;
	}

	private detectEcosystem(fileName: string): string | null {
		if (/^requirements.*\.txt$/.test(fileName)) return 'pypi';
		if (fileName === 'package.json') return 'npm';
		if (fileName === 'Cargo.toml') return 'crates';
		if (fileName === 'go.mod') return 'go';
		if (fileName === 'Gemfile') return 'rubygems';
		return null;
	}
}
