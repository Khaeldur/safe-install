import * as vscode from 'vscode';
import { SafeInstallBridge } from './safeInstallBridge';
import { DiagnosticsProvider } from './diagnostics';
import { PackageHoverProvider } from './hover';
import { StatusBarManager } from './statusBar';

const SUPPORTED_FILES = [
	'requirements.txt', 'requirements-dev.txt', 'requirements-prod.txt',
	'package.json', 'Cargo.toml', 'go.mod', 'Gemfile'
];

let statusBar: StatusBarManager | undefined;

export function activate(context: vscode.ExtensionContext) {
	const config = vscode.workspace.getConfiguration('safeInstall');
	const cliPath = config.get<string>('cliPath', 'safe-install');
	const bridge = new SafeInstallBridge(cliPath);

	const diagnosticsProvider = new DiagnosticsProvider(bridge);
	const hoverProvider = new PackageHoverProvider(bridge);
	statusBar = new StatusBarManager(bridge);

	context.subscriptions.push(diagnosticsProvider.diagnosticCollection);
	context.subscriptions.push(statusBar);

	const hoverSelectors: vscode.DocumentSelector = [
		{ pattern: '**/requirements*.txt' },
		{ pattern: '**/package.json' },
		{ pattern: '**/Cargo.toml' },
		{ pattern: '**/go.mod' },
		{ pattern: '**/Gemfile' },
	];

	if (config.get<boolean>('showHoverIntelligence', true)) {
		context.subscriptions.push(
			vscode.languages.registerHoverProvider(hoverSelectors, hoverProvider)
		);
	}

	context.subscriptions.push(
		vscode.commands.registerCommand('safeInstall.scanFile', async () => {
			const editor = vscode.window.activeTextEditor;
			if (!editor) {
				vscode.window.showWarningMessage('No active file to scan.');
				return;
			}
			await diagnosticsProvider.scanDocument(editor.document);
			vscode.window.showInformationMessage('Safe Install: Scan complete.');
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('safeInstall.auditPackage', async () => {
			const pkg = await vscode.window.showInputBox({
				prompt: 'Enter package name to audit',
				placeHolder: 'e.g. requests, lodash, serde'
			});
			if (!pkg) return;

			const ecosystem = await vscode.window.showQuickPick(
				['pypi', 'npm', 'crates', 'go', 'rubygems'],
				{ placeHolder: 'Select ecosystem' }
			);
			if (!ecosystem) return;

			try {
				const result = await bridge.auditPackage(pkg, ecosystem);
				const channel = vscode.window.createOutputChannel('Safe Install');
				channel.appendLine(`Audit results for ${pkg} (${ecosystem}):`);
				channel.appendLine(JSON.stringify(result, null, 2));
				channel.show();
			} catch (err: any) {
				vscode.window.showErrorMessage(`Audit failed: ${err.message}`);
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('safeInstall.toggleProtection', async () => {
			const current = config.get<boolean>('scanOnSave', true);
			await config.update('scanOnSave', !current, vscode.ConfigurationTarget.Workspace);
			const state = !current ? 'enabled' : 'disabled';
			vscode.window.showInformationMessage(`Safe Install: On-save scanning ${state}.`);
			statusBar?.update();
		})
	);

	if (config.get<boolean>('scanOnSave', true)) {
		context.subscriptions.push(
			vscode.workspace.onDidSaveTextDocument(async (document) => {
				const scanEnabled = vscode.workspace.getConfiguration('safeInstall').get<boolean>('scanOnSave', true);
				if (!scanEnabled) return;

				const fileName = document.fileName.split(/[\\/]/).pop() || '';
				if (SUPPORTED_FILES.some(f => fileName.match(new RegExp(f.replace('.', '\\.').replace('*', '.*'))))) {
					await diagnosticsProvider.scanDocument(document);
				}
			})
		);
	}

	context.subscriptions.push(
		vscode.workspace.onDidChangeConfiguration((e) => {
			if (e.affectsConfiguration('safeInstall')) {
				statusBar?.update();
			}
		})
	);

	statusBar.update();
}

export function deactivate() {
	statusBar?.dispose();
	statusBar = undefined;
}
