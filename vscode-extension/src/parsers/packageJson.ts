export interface ParsedPackage {
	name: string;
	line: number;
	versionSpec: string;
}

export function parsePackageJson(content: string): ParsedPackage[] {
	const packages: ParsedPackage[] = [];
	const lines = content.split('\n');

	let parsed: any;
	try {
		parsed = JSON.parse(content);
	} catch {
		return packages;
	}

	const depSections = ['dependencies', 'devDependencies', 'peerDependencies'];

	for (const section of depSections) {
		const deps = parsed[section];
		if (!deps || typeof deps !== 'object') continue;

		for (const [name, version] of Object.entries(deps)) {
			const lineNum = findPackageLine(lines, name);
			packages.push({
				name,
				line: lineNum,
				versionSpec: String(version),
			});
		}
	}

	return packages;
}

function findPackageLine(lines: string[], packageName: string): number {
	const escaped = packageName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
	const pattern = new RegExp(`"${escaped}"\\s*:`);

	for (let i = 0; i < lines.length; i++) {
		if (pattern.test(lines[i])) return i;
	}
	return 0;
}
