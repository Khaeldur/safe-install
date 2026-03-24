import * as vscode from 'vscode';
import { SafeInstallBridge } from './safeInstallBridge';
import { parseRequirements } from './parsers/requirements';
import { parsePackageJson } from './parsers/packageJson';

interface Finding {
	package: string;
	severity: string;
	message: string;
	type: string;
}

export class DiagnosticsProvider {
	public diagnosticCollection: vscode.DiagnosticCollection;

	constructor(private bridge: SafeInstallBridge) {
		this.diagnosticCollection = vscode.languages.createDiagnosticCollection('safe-install');
	}

	async scanDocument(document: vscode.TextDocument): Promise<void> {
		const fileName = document.fileName.split(/[\\/]/).pop() || '';
		const ecosystem = this.detectEcosystem(fileName);
		if (!ecosystem) return;

		const content = document.getText();
		let packages: Array<{ name: string; line: number; versionSpec: string }>;

		if (ecosystem === 'pypi') {
			packages = parseRequirements(content);
		} else if (ecosystem === 'npm') {
			packages = parsePackageJson(content);
		} else {
			// For unsupported parsers, fall back to file-level scan
			try {
				const result = await this.bridge.scanDepsFile(document.fileName);
				this.applyFileLevelFindings(document, result);
			} catch {
				// CLI not available or scan failed silently
			}
			return;
		}

		const diagnostics: vscode.Diagnostic[] = [];

		for (const pkg of packages) {
			try {
				const result = await this.bridge.auditPackage(pkg.name, ecosystem);
				if (!result?.findings) continue;

				for (const finding of result.findings as Finding[]) {
					const line = document.lineAt(pkg.line);
					const range = new vscode.Range(
						pkg.line, line.text.indexOf(pkg.name),
						pkg.line, line.text.indexOf(pkg.name) + pkg.name.length
					);

					const severity = this.mapSeverity(finding.severity);
					const diag = new vscode.Diagnostic(
						range,
						`[${finding.type}] ${finding.message}`,
						severity
					);
					diag.source = 'safe-install';
					diagnostics.push(diag);
				}
			} catch {
				// Skip packages that fail to audit
			}
		}

		this.diagnosticCollection.set(document.uri, diagnostics);
	}

	private applyFileLevelFindings(document: vscode.TextDocument, result: any): void {
		if (!result?.findings) return;

		const diagnostics: vscode.Diagnostic[] = [];
		for (const finding of result.findings as Finding[]) {
			const lineNum = finding.package
				? this.findLineForPackage(document, finding.package)
				: 0;
			const line = document.lineAt(lineNum);
			const range = new vscode.Range(lineNum, 0, lineNum, line.text.length);

			const diag = new vscode.Diagnostic(
				range,
				`[${finding.type}] ${finding.message}`,
				this.mapSeverity(finding.severity)
			);
			diag.source = 'safe-install';
			diagnostics.push(diag);
		}

		this.diagnosticCollection.set(document.uri, diagnostics);
	}

	private findLineForPackage(document: vscode.TextDocument, pkg: string): number {
		for (let i = 0; i < document.lineCount; i++) {
			if (document.lineAt(i).text.includes(pkg)) return i;
		}
		return 0;
	}

	private mapSeverity(severity: string): vscode.DiagnosticSeverity {
		switch (severity?.toUpperCase()) {
			case 'CRITICAL':
			case 'HIGH':
				return vscode.DiagnosticSeverity.Error;
			case 'MEDIUM':
				return vscode.DiagnosticSeverity.Warning;
			case 'LOW':
				return vscode.DiagnosticSeverity.Information;
			default:
				return vscode.DiagnosticSeverity.Information;
		}
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
