import * as vscode from 'vscode';
import { SafeInstallBridge } from './safeInstallBridge';

export class StatusBarManager {
	private item: vscode.StatusBarItem;

	constructor(private bridge: SafeInstallBridge) {
		this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
		this.item.command = 'safeInstall.toggleProtection';
		this.item.show();
	}

	async update(): Promise<void> {
		const config = vscode.workspace.getConfiguration('safeInstall');
		const scanOnSave = config.get<boolean>('scanOnSave', true);

		if (!scanOnSave) {
			this.item.text = '$(circle-slash) Safe Install';
			this.item.backgroundColor = undefined;
			this.item.tooltip = 'Safe Install: Protection disabled (click to enable)';
			this.item.color = new vscode.ThemeColor('disabledForeground');
			return;
		}

		const available = await this.bridge.isAvailable();
		if (!available) {
			this.item.text = '$(circle-slash) Safe Install';
			this.item.backgroundColor = undefined;
			this.item.tooltip = 'Safe Install: CLI not found';
			this.item.color = new vscode.ThemeColor('disabledForeground');
			return;
		}

		try {
			const status = await this.bridge.getStatus();

			if (status.alerts && status.alerts > 0) {
				this.item.text = `$(error) Safe Install (${status.alerts})`;
				this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
				this.item.color = undefined;
				this.item.tooltip = `Safe Install: ${status.alerts} alert(s) found`;
			} else if (status.warnings && status.warnings > 0) {
				this.item.text = `$(warning) Safe Install (${status.warnings})`;
				this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
				this.item.color = undefined;
				this.item.tooltip = `Safe Install: ${status.warnings} warning(s)`;
			} else {
				this.item.text = '$(shield) Safe Install';
				this.item.backgroundColor = undefined;
				this.item.color = new vscode.ThemeColor('testing.iconPassed');
				this.item.tooltip = 'Safe Install: Protected';
			}
		} catch {
			this.item.text = '$(shield) Safe Install';
			this.item.backgroundColor = undefined;
			this.item.color = new vscode.ThemeColor('testing.iconPassed');
			this.item.tooltip = 'Safe Install: Active';
		}
	}

	dispose(): void {
		this.item.dispose();
	}
}
