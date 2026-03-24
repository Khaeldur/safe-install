export interface ParsedPackage {
	name: string;
	line: number;
	versionSpec: string;
}

export function parseRequirements(content: string): ParsedPackage[] {
	const packages: ParsedPackage[] = [];
	const lines = content.split('\n');

	for (let i = 0; i < lines.length; i++) {
		const raw = lines[i].trim();
		if (!raw || raw.startsWith('#') || raw.startsWith('-')) continue;

		const match = raw.match(/^([a-zA-Z0-9_-][a-zA-Z0-9._-]*)\s*([><=!~].*)?$/);
		if (match) {
			packages.push({
				name: match[1],
				line: i,
				versionSpec: (match[2] || '').trim(),
			});
		}
	}

	return packages;
}
