import { execFile } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';

const execFileAsync = promisify(execFile);

export class SafeInstallBridge {
	constructor(private cliPath: string) {}

	async auditPackage(pkg: string, ecosystem: string): Promise<any> {
		return this.exec(['api', 'audit', pkg, '-e', ecosystem, '--json']);
	}

	async scanDepsFile(filePath: string): Promise<any> {
		return this.exec(['api', 'scan-deps', filePath, '--json']);
	}

	async checkTyposquat(pkg: string, ecosystem: string): Promise<any> {
		return this.exec(['api', 'check-typosquat', pkg, '-e', ecosystem, '--json']);
	}

	async getIntelligence(pkg: string, ecosystem: string): Promise<any> {
		return this.exec(['api', 'intelligence', pkg, '-e', ecosystem, '--json']);
	}

	async getStatus(): Promise<any> {
		return this.exec(['api', 'status', '--json']);
	}

	async isAvailable(): Promise<boolean> {
		try {
			const resolvedPath = this.cliPath.includes('/') || this.cliPath.includes('\\')
				? this.cliPath
				: this.cliPath;

			await execFileAsync(resolvedPath, ['--version']);
			return true;
		} catch {
			return false;
		}
	}

	private async exec(args: string[]): Promise<any> {
		try {
			const { stdout } = await execFileAsync(this.cliPath, args, {
				timeout: 30_000,
				maxBuffer: 10 * 1024 * 1024,
			});
			return JSON.parse(stdout);
		} catch (err: any) {
			if (err.stdout) {
				try {
					return JSON.parse(err.stdout);
				} catch {}
			}
			throw new Error(
				`safe-install CLI failed: ${err.message || 'unknown error'}`
			);
		}
	}
}
